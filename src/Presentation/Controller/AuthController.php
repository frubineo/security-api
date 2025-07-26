<?php

declare(strict_types=1);

namespace SecurityApi\Presentation\Controller;

use SecurityApi\Application\UseCase\AuthenticateUserUseCase;
use SecurityApi\Application\UseCase\RefreshTokenUseCase;
use SecurityApi\Application\UseCase\RevokeTokenUseCase;
use SecurityApi\Application\UseCase\GenerateApiKeyUseCase;
use SecurityApi\Application\UseCase\EnableMfaUseCase;
use SecurityApi\Application\UseCase\ValidateMfaUseCase;
use SecurityApi\Application\DTO\AuthenticationRequest;
use SecurityApi\Application\DTO\RefreshTokenRequest;
use SecurityApi\Application\DTO\MfaValidationRequest;
use SecurityApi\Domain\Entity\SecurityAuditLog;
use SecurityApi\Infrastructure\Security\SecurityAuditor;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;
use Symfony\Component\RateLimiter\RateLimiterFactory;
use Symfony\Component\Validator\Validator\ValidatorInterface;
use Psr\Log\LoggerInterface;

/**
 * Contrôleur central d'authentification
 * 
 * Hub principal pour tous les services d'authentification
 */
#[Route('/api/v1/auth', name: 'security_auth_')]
class AuthController extends AbstractController
{
    public function __construct(
        private readonly AuthenticateUserUseCase $authenticateUserUseCase,
        private readonly RefreshTokenUseCase $refreshTokenUseCase,
        private readonly RevokeTokenUseCase $revokeTokenUseCase,
        private readonly GenerateApiKeyUseCase $generateApiKeyUseCase,
        private readonly EnableMfaUseCase $enableMfaUseCase,
        private readonly ValidateMfaUseCase $validateMfaUseCase,
        private readonly SecurityAuditor $securityAuditor,
        private readonly ValidatorInterface $validator,
        private readonly LoggerInterface $logger,
        private readonly RateLimiterFactory $authLimiter
    ) {
    }

    /**
     * Authentification centralisée
     */
    #[Route('/login', name: 'login', methods: ['POST'])]
    public function login(Request $request): JsonResponse
    {
        $ipAddress = $this->getClientIp($request);
        
        // Rate limiting strict pour l'authentification
        $limiter = $this->authLimiter->create($ipAddress);
        if (!$limiter->consume(1)->isAccepted()) {
            $this->securityAuditor->logEvent(
                SecurityAuditLog::EVENT_LOGIN_BLOCKED,
                SecurityAuditLog::SEVERITY_HIGH,
                'Login attempt blocked by rate limiter',
                $ipAddress,
                $request->headers->get('User-Agent')
            );

            return $this->json([
                'error' => 'Rate limit exceeded',
                'message' => 'Too many login attempts. Please try again later.',
            ], Response::HTTP_TOO_MANY_REQUESTS);
        }

        try {
            $data = json_decode($request->getContent(), true);
            
            $authRequest = new AuthenticationRequest(
                email: $data['email'] ?? '',
                password: $data['password'] ?? '',
                mfaCode: $data['mfa_code'] ?? null,
                ipAddress: $ipAddress,
                userAgent: $request->headers->get('User-Agent'),
                rememberMe: $data['remember_me'] ?? false
            );

            $violations = $this->validator->validate($authRequest);
            if (count($violations) > 0) {
                return $this->json([
                    'error' => 'Validation failed',
                    'violations' => $this->formatViolations($violations)
                ], Response::HTTP_BAD_REQUEST);
            }

            $result = $this->authenticateUserUseCase->execute($authRequest);

            $this->logger->info('User authentication successful', [
                'user_id' => $result->userId,
                'ip_address' => $ipAddress
            ]);

            return $this->json($result->toArray(), Response::HTTP_OK);

        } catch (\InvalidArgumentException $e) {
            return $this->json([
                'error' => 'Invalid credentials',
                'message' => 'The provided credentials are invalid.'
            ], Response::HTTP_UNAUTHORIZED);

        } catch (\Exception $e) {
            $this->logger->error('Authentication error', [
                'error' => $e->getMessage(),
                'ip_address' => $ipAddress
            ]);

            return $this->json([
                'error' => 'Authentication failed',
                'message' => 'An error occurred during authentication.'
            ], Response::HTTP_INTERNAL_SERVER_ERROR);
        }
    }

    /**
     * Refresh des tokens JWT
     */
    #[Route('/refresh', name: 'refresh', methods: ['POST'])]
    public function refresh(Request $request): JsonResponse
    {
        try {
            $data = json_decode($request->getContent(), true);
            
            $refreshRequest = new RefreshTokenRequest(
                refreshToken: $data['refresh_token'] ?? '',
                ipAddress: $this->getClientIp($request),
                userAgent: $request->headers->get('User-Agent')
            );

            $violations = $this->validator->validate($refreshRequest);
            if (count($violations) > 0) {
                return $this->json([
                    'error' => 'Validation failed',
                    'violations' => $this->formatViolations($violations)
                ], Response::HTTP_BAD_REQUEST);
            }

            $result = $this->refreshTokenUseCase->execute($refreshRequest);

            return $this->json($result->toArray(), Response::HTTP_OK);

        } catch (\InvalidArgumentException $e) {
            return $this->json([
                'error' => 'Invalid refresh token',
                'message' => $e->getMessage()
            ], Response::HTTP_UNAUTHORIZED);

        } catch (\Exception $e) {
            $this->logger->error('Token refresh error', [
                'error' => $e->getMessage(),
                'ip_address' => $this->getClientIp($request)
            ]);

            return $this->json([
                'error' => 'Token refresh failed',
                'message' => 'An error occurred during token refresh.'
            ], Response::HTTP_INTERNAL_SERVER_ERROR);
        }
    }

    /**
     * Révocation de token
     */
    #[Route('/revoke', name: 'revoke', methods: ['POST'])]
    public function revoke(Request $request): JsonResponse
    {
        try {
            $data = json_decode($request->getContent(), true);
            
            $this->revokeTokenUseCase->execute(
                tokenId: $data['token_id'] ?? '',
                reason: $data['reason'] ?? 'Manual revocation',
                ipAddress: $this->getClientIp($request)
            );

            return $this->json([
                'message' => 'Token revoked successfully'
            ], Response::HTTP_OK);

        } catch (\Exception $e) {
            $this->logger->error('Token revocation error', [
                'error' => $e->getMessage(),
                'ip_address' => $this->getClientIp($request)
            ]);

            return $this->json([
                'error' => 'Token revocation failed',
                'message' => $e->getMessage()
            ], Response::HTTP_INTERNAL_SERVER_ERROR);
        }
    }

    /**
     * Logout (révoque tous les tokens de l'utilisateur)
     */
    #[Route('/logout', name: 'logout', methods: ['POST'])]
    public function logout(Request $request): JsonResponse
    {
        try {
            $user = $this->getUser();
            if (!$user) {
                return $this->json([
                    'error' => 'Not authenticated'
                ], Response::HTTP_UNAUTHORIZED);
            }

            // Révoquer tous les tokens actifs de l'utilisateur
            $this->revokeTokenUseCase->revokeAllUserTokens(
                userId: $user->getId()->toString(),
                reason: 'Logout',
                ipAddress: $this->getClientIp($request)
            );

            return $this->json([
                'message' => 'Logged out successfully'
            ], Response::HTTP_OK);

        } catch (\Exception $e) {
            $this->logger->error('Logout error', [
                'error' => $e->getMessage(),
                'ip_address' => $this->getClientIp($request)
            ]);

            return $this->json([
                'error' => 'Logout failed',
                'message' => $e->getMessage()
            ], Response::HTTP_INTERNAL_SERVER_ERROR);
        }
    }

    /**
     * Génération d'API Key
     */
    #[Route('/api-key/generate', name: 'generate_api_key', methods: ['POST'])]
    public function generateApiKey(Request $request): JsonResponse
    {
        try {
            $user = $this->getUser();
            if (!$user) {
                return $this->json([
                    'error' => 'Not authenticated'
                ], Response::HTTP_UNAUTHORIZED);
            }

            $data = json_decode($request->getContent(), true);
            
            $result = $this->generateApiKeyUseCase->execute(
                userId: $user->getId()->toString(),
                name: $data['name'] ?? 'Generated API Key',
                scopes: $data['scopes'] ?? [],
                expiresAt: isset($data['expires_at']) ? 
                    new \DateTimeImmutable($data['expires_at']) : null,
                ipAddress: $this->getClientIp($request)
            );

            return $this->json($result->toArray(), Response::HTTP_CREATED);

        } catch (\Exception $e) {
            $this->logger->error('API key generation error', [
                'error' => $e->getMessage(),
                'ip_address' => $this->getClientIp($request)
            ]);

            return $this->json([
                'error' => 'API key generation failed',
                'message' => $e->getMessage()
            ], Response::HTTP_INTERNAL_SERVER_ERROR);
        }
    }

    /**
     * Configuration MFA
     */
    #[Route('/mfa/enable', name: 'enable_mfa', methods: ['POST'])]
    public function enableMfa(Request $request): JsonResponse
    {
        try {
            $user = $this->getUser();
            if (!$user) {
                return $this->json([
                    'error' => 'Not authenticated'
                ], Response::HTTP_UNAUTHORIZED);
            }

            $result = $this->enableMfaUseCase->execute(
                userId: $user->getId()->toString(),
                ipAddress: $this->getClientIp($request)
            );

            return $this->json($result->toArray(), Response::HTTP_OK);

        } catch (\Exception $e) {
            $this->logger->error('MFA enable error', [
                'error' => $e->getMessage(),
                'user_id' => $this->getUser()?->getId()->toString(),
                'ip_address' => $this->getClientIp($request)
            ]);

            return $this->json([
                'error' => 'MFA enable failed',
                'message' => $e->getMessage()
            ], Response::HTTP_INTERNAL_SERVER_ERROR);
        }
    }

    /**
     * Validation MFA
     */
    #[Route('/mfa/validate', name: 'validate_mfa', methods: ['POST'])]
    public function validateMfa(Request $request): JsonResponse
    {
        try {
            $user = $this->getUser();
            if (!$user) {
                return $this->json([
                    'error' => 'Not authenticated'
                ], Response::HTTP_UNAUTHORIZED);
            }

            $data = json_decode($request->getContent(), true);
            
            $mfaRequest = new MfaValidationRequest(
                userId: $user->getId()->toString(),
                code: $data['code'] ?? '',
                ipAddress: $this->getClientIp($request)
            );

            $violations = $this->validator->validate($mfaRequest);
            if (count($violations) > 0) {
                return $this->json([
                    'error' => 'Validation failed',
                    'violations' => $this->formatViolations($violations)
                ], Response::HTTP_BAD_REQUEST);
            }

            $result = $this->validateMfaUseCase->execute($mfaRequest);

            return $this->json($result->toArray(), Response::HTTP_OK);

        } catch (\Exception $e) {
            $this->logger->error('MFA validation error', [
                'error' => $e->getMessage(),
                'user_id' => $this->getUser()?->getId()->toString(),
                'ip_address' => $this->getClientIp($request)
            ]);

            return $this->json([
                'error' => 'MFA validation failed',
                'message' => $e->getMessage()
            ], Response::HTTP_INTERNAL_SERVER_ERROR);
        }
    }

    /**
     * Informations sur l'utilisateur authentifié
     */
    #[Route('/me', name: 'me', methods: ['GET'])]
    public function me(): JsonResponse
    {
        $user = $this->getUser();
        if (!$user) {
            return $this->json([
                'error' => 'Not authenticated'
            ], Response::HTTP_UNAUTHORIZED);
        }

        return $this->json([
            'id' => $user->getId()->toString(),
            'username' => $user->getUsername(),
            'email' => $user->getEmail()->toString(),
            'role' => $user->getRole()->toString(),
            'status' => $user->getStatus()->toString(),
            'mfa_enabled' => $user->isMfaEnabled(),
            'created_at' => $user->getCreatedAt()->format(\DateTimeInterface::ATOM),
            'last_login_at' => $user->getLastLoginAt()?->format(\DateTimeInterface::ATOM),
        ], Response::HTTP_OK);
    }

    private function getClientIp(Request $request): string
    {
        return $request->getClientIp() ?? '127.0.0.1';
    }

    private function formatViolations($violations): array
    {
        $errors = [];
        foreach ($violations as $violation) {
            $errors[] = [
                'property' => $violation->getPropertyPath(),
                'message' => $violation->getMessage(),
            ];
        }
        return $errors;
    }
} 