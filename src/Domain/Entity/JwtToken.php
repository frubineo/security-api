<?php

declare(strict_types=1);

namespace SecurityApi\Domain\Entity;

use SecurityApi\Domain\ValueObject\UserId;
use Doctrine\ORM\Mapping as ORM;
use Ramsey\Uuid\Uuid;

/**
 * Entité pour la gestion centralisée des tokens JWT
 * 
 * Permet le tracking, la révocation et l'audit des tokens
 */
#[ORM\Entity]
#[ORM\Table(name: 'jwt_tokens')]
#[ORM\Index(columns: ['token_id'], name: 'idx_token_id')]
#[ORM\Index(columns: ['user_id'], name: 'idx_token_user')]
#[ORM\Index(columns: ['expires_at'], name: 'idx_token_expiry')]
#[ORM\Index(columns: ['is_revoked'], name: 'idx_token_revoked')]
class JwtToken
{
    #[ORM\Id]
    #[ORM\Column(type: 'uuid')]
    private string $id;

    #[ORM\Column(type: 'string', length: 64, unique: true)]
    private string $tokenId;

    #[ORM\ManyToOne(targetEntity: User::class, inversedBy: 'jwtTokens')]
    #[ORM\JoinColumn(name: 'user_id', referencedColumnName: 'id', nullable: false)]
    private User $user;

    #[ORM\Column(type: 'text')]
    private string $tokenHash;

    #[ORM\Column(type: 'datetime_immutable')]
    private \DateTimeImmutable $issuedAt;

    #[ORM\Column(type: 'datetime_immutable')]
    private \DateTimeImmutable $expiresAt;

    #[ORM\Column(type: 'string', length: 45)]
    private string $ipAddress;

    #[ORM\Column(type: 'text', nullable: true)]
    private ?string $userAgent = null;

    #[ORM\Column(type: 'string', length: 50)]
    private string $tokenType = 'access';

    #[ORM\Column(type: 'boolean', options: ['default' => false])]
    private bool $isRevoked = false;

    #[ORM\Column(type: 'datetime_immutable', nullable: true)]
    private ?\DateTimeImmutable $revokedAt = null;

    #[ORM\Column(type: 'string', length: 255, nullable: true)]
    private ?string $revokedReason = null;

    #[ORM\Column(type: 'datetime_immutable', nullable: true)]
    private ?\DateTimeImmutable $lastUsedAt = null;

    #[ORM\Column(type: 'integer', options: ['default' => 0])]
    private int $usageCount = 0;

    #[ORM\Column(type: 'json', nullable: true)]
    private ?array $scopes = null;

    #[ORM\Column(type: 'json', nullable: true)]
    private ?array $claims = null;

    public function __construct(
        User $user,
        string $tokenHash,
        \DateTimeImmutable $expiresAt,
        string $ipAddress,
        ?string $userAgent = null,
        string $tokenType = 'access',
        ?array $scopes = null,
        ?array $claims = null
    ) {
        $this->id = Uuid::uuid4()->toString();
        $this->tokenId = $this->generateTokenId();
        $this->user = $user;
        $this->tokenHash = $tokenHash;
        $this->issuedAt = new \DateTimeImmutable();
        $this->expiresAt = $expiresAt;
        $this->ipAddress = $ipAddress;
        $this->userAgent = $userAgent;
        $this->tokenType = $tokenType;
        $this->scopes = $scopes;
        $this->claims = $claims;
    }

    // Getters
    public function getId(): string
    {
        return $this->id;
    }

    public function getTokenId(): string
    {
        return $this->tokenId;
    }

    public function getUser(): User
    {
        return $this->user;
    }

    public function getTokenHash(): string
    {
        return $this->tokenHash;
    }

    public function getIssuedAt(): \DateTimeImmutable
    {
        return $this->issuedAt;
    }

    public function getExpiresAt(): \DateTimeImmutable
    {
        return $this->expiresAt;
    }

    public function getIpAddress(): string
    {
        return $this->ipAddress;
    }

    public function getUserAgent(): ?string
    {
        return $this->userAgent;
    }

    public function getTokenType(): string
    {
        return $this->tokenType;
    }

    public function isRevoked(): bool
    {
        return $this->isRevoked;
    }

    public function getRevokedAt(): ?\DateTimeImmutable
    {
        return $this->revokedAt;
    }

    public function getRevokedReason(): ?string
    {
        return $this->revokedReason;
    }

    public function getLastUsedAt(): ?\DateTimeImmutable
    {
        return $this->lastUsedAt;
    }

    public function getUsageCount(): int
    {
        return $this->usageCount;
    }

    public function getScopes(): ?array
    {
        return $this->scopes;
    }

    public function getClaims(): ?array
    {
        return $this->claims;
    }

    // Business Methods
    public function isExpired(): bool
    {
        return $this->expiresAt < new \DateTimeImmutable();
    }

    public function isValid(): bool
    {
        return !$this->isRevoked && !$this->isExpired();
    }

    public function revoke(string $reason = 'Manual revocation'): void
    {
        $this->isRevoked = true;
        $this->revokedAt = new \DateTimeImmutable();
        $this->revokedReason = $reason;
    }

    public function recordUsage(): void
    {
        $this->lastUsedAt = new \DateTimeImmutable();
        $this->usageCount++;
    }

    public function hasScope(string $scope): bool
    {
        if ($this->scopes === null) {
            return false;
        }

        return in_array($scope, $this->scopes, true);
    }

    public function getClaim(string $claim): mixed
    {
        return $this->claims[$claim] ?? null;
    }

    public function isAccessToken(): bool
    {
        return $this->tokenType === 'access';
    }

    public function isRefreshToken(): bool
    {
        return $this->tokenType === 'refresh';
    }

    public function getRemainingLifetime(): int
    {
        if ($this->isExpired()) {
            return 0;
        }

        return $this->expiresAt->getTimestamp() - time();
    }

    public function getLifetimeInSeconds(): int
    {
        return $this->expiresAt->getTimestamp() - $this->issuedAt->getTimestamp();
    }

    public function isFromSameClient(string $ipAddress, ?string $userAgent = null): bool
    {
        $sameIp = $this->ipAddress === $ipAddress;
        
        if ($userAgent === null || $this->userAgent === null) {
            return $sameIp;
        }

        return $sameIp && $this->userAgent === $userAgent;
    }

    private function generateTokenId(): string
    {
        return 'jti_' . bin2hex(random_bytes(24)); // 54 characters total
    }

    public function toArray(): array
    {
        return [
            'id' => $this->id,
            'token_id' => $this->tokenId,
            'user_id' => $this->user->getId()->toString(),
            'token_type' => $this->tokenType,
            'issued_at' => $this->issuedAt->format(\DateTimeInterface::ATOM),
            'expires_at' => $this->expiresAt->format(\DateTimeInterface::ATOM),
            'ip_address' => $this->ipAddress,
            'user_agent' => $this->userAgent,
            'is_revoked' => $this->isRevoked,
            'revoked_at' => $this->revokedAt?->format(\DateTimeInterface::ATOM),
            'revoked_reason' => $this->revokedReason,
            'last_used_at' => $this->lastUsedAt?->format(\DateTimeInterface::ATOM),
            'usage_count' => $this->usageCount,
            'scopes' => $this->scopes,
            'claims' => $this->claims,
            'is_expired' => $this->isExpired(),
            'is_valid' => $this->isValid(),
            'remaining_lifetime' => $this->getRemainingLifetime(),
        ];
    }
} 