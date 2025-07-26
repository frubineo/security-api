<?php

declare(strict_types=1);

namespace SecurityApi\Domain\Entity;

use SecurityApi\Domain\ValueObject\Email;
use SecurityApi\Domain\ValueObject\UserId;
use SecurityApi\Domain\ValueObject\UserRole;
use SecurityApi\Domain\ValueObject\UserStatus;
use Doctrine\Common\Collections\ArrayCollection;
use Doctrine\Common\Collections\Collection;
use Doctrine\ORM\Mapping as ORM;

/**
 * Entité User du domaine sécurité
 * 
 * Hub central pour l'authentification et l'autorisation
 * Respecte les principes DDD avec Value Objects
 */
#[ORM\Entity]
#[ORM\Table(name: 'users')]
#[ORM\Index(columns: ['email'], name: 'idx_user_email')]
#[ORM\Index(columns: ['api_key'], name: 'idx_user_api_key')]
#[ORM\Index(columns: ['status'], name: 'idx_user_status')]
class User
{
    #[ORM\Id]
    #[ORM\Column(type: 'uuid')]
    private UserId $id;

    #[ORM\Embedded(class: Email::class)]
    private Email $email;

    #[ORM\Column(type: 'string', length: 255)]
    private string $username;

    #[ORM\Column(type: 'string', length: 255)]
    private string $passwordHash;

    #[ORM\Column(type: 'string', length: 64, unique: true)]
    private string $apiKey;

    #[ORM\Embedded(class: UserRole::class)]
    private UserRole $role;

    #[ORM\Embedded(class: UserStatus::class)]
    private UserStatus $status;

    #[ORM\Column(type: 'datetime_immutable')]
    private \DateTimeImmutable $createdAt;

    #[ORM\Column(type: 'datetime_immutable', nullable: true)]
    private ?\DateTimeImmutable $lastLoginAt = null;

    #[ORM\Column(type: 'datetime_immutable', nullable: true)]
    private ?\DateTimeImmutable $lastPasswordChangeAt = null;

    #[ORM\Column(type: 'integer', options: ['default' => 0])]
    private int $failedLoginAttempts = 0;

    #[ORM\Column(type: 'datetime_immutable', nullable: true)]
    private ?\DateTimeImmutable $lockedUntil = null;

    #[ORM\Column(type: 'boolean', options: ['default' => false])]
    private bool $mfaEnabled = false;

    #[ORM\Column(type: 'string', length: 32, nullable: true)]
    private ?string $mfaSecret = null;

    #[ORM\Column(type: 'json', nullable: true)]
    private ?array $mfaBackupCodes = null;

    #[ORM\Column(type: 'json', nullable: true)]
    private ?array $allowedIpAddresses = null;

    #[ORM\Column(type: 'json', nullable: true)]
    private ?array $metadata = null;

    #[ORM\OneToMany(mappedBy: 'user', targetEntity: JwtToken::class, cascade: ['persist', 'remove'])]
    private Collection $jwtTokens;

    #[ORM\OneToMany(mappedBy: 'user', targetEntity: SecurityAuditLog::class, cascade: ['persist'])]
    private Collection $auditLogs;

    #[ORM\OneToMany(mappedBy: 'user', targetEntity: LoginSession::class, cascade: ['persist', 'remove'])]
    private Collection $loginSessions;

    public function __construct(
        UserId $id,
        Email $email,
        string $username,
        string $passwordHash,
        UserRole $role = null
    ) {
        $this->id = $id;
        $this->email = $email;
        $this->username = $username;
        $this->passwordHash = $passwordHash;
        $this->role = $role ?? UserRole::user();
        $this->status = UserStatus::active();
        $this->apiKey = $this->generateApiKey();
        $this->createdAt = new \DateTimeImmutable();
        $this->jwtTokens = new ArrayCollection();
        $this->auditLogs = new ArrayCollection();
        $this->loginSessions = new ArrayCollection();
    }

    // Getters
    public function getId(): UserId
    {
        return $this->id;
    }

    public function getEmail(): Email
    {
        return $this->email;
    }

    public function getUsername(): string
    {
        return $this->username;
    }

    public function getPasswordHash(): string
    {
        return $this->passwordHash;
    }

    public function getApiKey(): string
    {
        return $this->apiKey;
    }

    public function getRole(): UserRole
    {
        return $this->role;
    }

    public function getStatus(): UserStatus
    {
        return $this->status;
    }

    public function getCreatedAt(): \DateTimeImmutable
    {
        return $this->createdAt;
    }

    public function getLastLoginAt(): ?\DateTimeImmutable
    {
        return $this->lastLoginAt;
    }

    public function getFailedLoginAttempts(): int
    {
        return $this->failedLoginAttempts;
    }

    public function getLockedUntil(): ?\DateTimeImmutable
    {
        return $this->lockedUntil;
    }

    public function isMfaEnabled(): bool
    {
        return $this->mfaEnabled;
    }

    public function getMfaSecret(): ?string
    {
        return $this->mfaSecret;
    }

    public function getAllowedIpAddresses(): ?array
    {
        return $this->allowedIpAddresses;
    }

    /**
     * @return Collection<int, JwtToken>
     */
    public function getJwtTokens(): Collection
    {
        return $this->jwtTokens;
    }

    /**
     * @return Collection<int, SecurityAuditLog>
     */
    public function getAuditLogs(): Collection
    {
        return $this->auditLogs;
    }

    // Business Methods
    public function changePassword(string $newPasswordHash): void
    {
        $this->passwordHash = $newPasswordHash;
        $this->lastPasswordChangeAt = new \DateTimeImmutable();
        $this->failedLoginAttempts = 0;
        $this->lockedUntil = null;
    }

    public function recordSuccessfulLogin(string $ipAddress): void
    {
        $this->lastLoginAt = new \DateTimeImmutable();
        $this->failedLoginAttempts = 0;
        $this->lockedUntil = null;
    }

    public function recordFailedLogin(): void
    {
        $this->failedLoginAttempts++;
        
        // Lock account after 5 failed attempts for 30 minutes
        if ($this->failedLoginAttempts >= 5) {
            $this->lockedUntil = new \DateTimeImmutable('+30 minutes');
        }
    }

    public function isLocked(): bool
    {
        if ($this->lockedUntil === null) {
            return false;
        }

        return $this->lockedUntil > new \DateTimeImmutable();
    }

    public function unlockAccount(): void
    {
        $this->lockedUntil = null;
        $this->failedLoginAttempts = 0;
    }

    public function enableMfa(string $secret): void
    {
        $this->mfaEnabled = true;
        $this->mfaSecret = $secret;
        $this->mfaBackupCodes = $this->generateBackupCodes();
    }

    public function disableMfa(): void
    {
        $this->mfaEnabled = false;
        $this->mfaSecret = null;
        $this->mfaBackupCodes = null;
    }

    public function regenerateApiKey(): void
    {
        $this->apiKey = $this->generateApiKey();
    }

    public function changeRole(UserRole $newRole): void
    {
        $this->role = $newRole;
    }

    public function activate(): void
    {
        $this->status = UserStatus::active();
    }

    public function deactivate(): void
    {
        $this->status = UserStatus::inactive();
    }

    public function suspend(): void
    {
        $this->status = UserStatus::suspended();
    }

    public function setAllowedIpAddresses(array $ipAddresses): void
    {
        $this->allowedIpAddresses = $ipAddresses;
    }

    public function isIpAddressAllowed(string $ipAddress): bool
    {
        if ($this->allowedIpAddresses === null || empty($this->allowedIpAddresses)) {
            return true; // No IP restrictions
        }

        return in_array($ipAddress, $this->allowedIpAddresses, true);
    }

    public function hasRole(string $role): bool
    {
        return $this->role->hasRole($role);
    }

    public function isActive(): bool
    {
        return $this->status->isActive() && !$this->isLocked();
    }

    public function canLogin(string $ipAddress): bool
    {
        return $this->isActive() && $this->isIpAddressAllowed($ipAddress);
    }

    private function generateApiKey(): string
    {
        return 'bims_' . bin2hex(random_bytes(28)); // 64 characters total
    }

    private function generateBackupCodes(): array
    {
        $codes = [];
        for ($i = 0; $i < 10; $i++) {
            $codes[] = str_pad((string) random_int(100000, 999999), 6, '0', STR_PAD_LEFT);
        }
        return $codes;
    }

    public function setMetadata(array $metadata): void
    {
        $this->metadata = $metadata;
    }

    public function getMetadata(): ?array
    {
        return $this->metadata;
    }

    public function addMetadata(string $key, mixed $value): void
    {
        if ($this->metadata === null) {
            $this->metadata = [];
        }
        $this->metadata[$key] = $value;
    }
} 