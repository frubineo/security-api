<?php

declare(strict_types=1);

namespace SecurityApi\Domain\Entity;

use Doctrine\ORM\Mapping as ORM;
use Ramsey\Uuid\Uuid;

/**
 * Entité pour tracker les sessions de connexion
 * 
 * Permet le suivi et la gestion des sessions actives
 */
#[ORM\Entity]
#[ORM\Table(name: 'login_sessions')]
#[ORM\Index(columns: ['user_id'], name: 'idx_session_user')]
#[ORM\Index(columns: ['session_id'], name: 'idx_session_id')]
#[ORM\Index(columns: ['is_active'], name: 'idx_session_active')]
#[ORM\Index(columns: ['created_at'], name: 'idx_session_created')]
class LoginSession
{
    #[ORM\Id]
    #[ORM\Column(type: 'uuid')]
    private string $id;

    #[ORM\Column(type: 'string', length: 128, unique: true)]
    private string $sessionId;

    #[ORM\ManyToOne(targetEntity: User::class, inversedBy: 'loginSessions')]
    #[ORM\JoinColumn(name: 'user_id', referencedColumnName: 'id', nullable: false)]
    private User $user;

    #[ORM\Column(type: 'string', length: 45)]
    private string $ipAddress;

    #[ORM\Column(type: 'text', nullable: true)]
    private ?string $userAgent = null;

    #[ORM\Column(type: 'datetime_immutable')]
    private \DateTimeImmutable $createdAt;

    #[ORM\Column(type: 'datetime_immutable', nullable: true)]
    private ?\DateTimeImmutable $lastActivityAt = null;

    #[ORM\Column(type: 'datetime_immutable', nullable: true)]
    private ?\DateTimeImmutable $expiresAt = null;

    #[ORM\Column(type: 'boolean', options: ['default' => true])]
    private bool $isActive = true;

    #[ORM\Column(type: 'datetime_immutable', nullable: true)]
    private ?\DateTimeImmutable $endedAt = null;

    #[ORM\Column(type: 'string', length: 100, nullable: true)]
    private ?string $endReason = null;

    #[ORM\Column(type: 'json', nullable: true)]
    private ?array $metadata = null;

    #[ORM\Column(type: 'integer', options: ['default' => 0])]
    private int $requestCount = 0;

    #[ORM\Column(type: 'datetime_immutable', nullable: true)]
    private ?\DateTimeImmutable $lastIpChangeAt = null;

    #[ORM\Column(type: 'string', length: 45, nullable: true)]
    private ?string $previousIpAddress = null;

    public function __construct(
        User $user,
        string $ipAddress,
        ?string $userAgent = null,
        ?\DateTimeImmutable $expiresAt = null
    ) {
        $this->id = Uuid::uuid4()->toString();
        $this->sessionId = $this->generateSessionId();
        $this->user = $user;
        $this->ipAddress = $ipAddress;
        $this->userAgent = $userAgent;
        $this->createdAt = new \DateTimeImmutable();
        $this->lastActivityAt = new \DateTimeImmutable();
        $this->expiresAt = $expiresAt ?? new \DateTimeImmutable('+24 hours');
    }

    // Getters
    public function getId(): string
    {
        return $this->id;
    }

    public function getSessionId(): string
    {
        return $this->sessionId;
    }

    public function getUser(): User
    {
        return $this->user;
    }

    public function getIpAddress(): string
    {
        return $this->ipAddress;
    }

    public function getUserAgent(): ?string
    {
        return $this->userAgent;
    }

    public function getCreatedAt(): \DateTimeImmutable
    {
        return $this->createdAt;
    }

    public function getLastActivityAt(): ?\DateTimeImmutable
    {
        return $this->lastActivityAt;
    }

    public function getExpiresAt(): ?\DateTimeImmutable
    {
        return $this->expiresAt;
    }

    public function isActive(): bool
    {
        return $this->isActive;
    }

    public function getEndedAt(): ?\DateTimeImmutable
    {
        return $this->endedAt;
    }

    public function getEndReason(): ?string
    {
        return $this->endReason;
    }

    public function getMetadata(): ?array
    {
        return $this->metadata;
    }

    public function getRequestCount(): int
    {
        return $this->requestCount;
    }

    public function getLastIpChangeAt(): ?\DateTimeImmutable
    {
        return $this->lastIpChangeAt;
    }

    public function getPreviousIpAddress(): ?string
    {
        return $this->previousIpAddress;
    }

    // Business Methods
    public function isExpired(): bool
    {
        if ($this->expiresAt === null) {
            return false;
        }

        return $this->expiresAt < new \DateTimeImmutable();
    }

    public function isValid(): bool
    {
        return $this->isActive && !$this->isExpired();
    }

    public function recordActivity(?string $ipAddress = null): void
    {
        $this->lastActivityAt = new \DateTimeImmutable();
        $this->requestCount++;

        // Track IP address changes
        if ($ipAddress !== null && $ipAddress !== $this->ipAddress) {
            $this->previousIpAddress = $this->ipAddress;
            $this->ipAddress = $ipAddress;
            $this->lastIpChangeAt = new \DateTimeImmutable();
        }
    }

    public function end(string $reason = 'Manual logout'): void
    {
        $this->isActive = false;
        $this->endedAt = new \DateTimeImmutable();
        $this->endReason = $reason;
    }

    public function extend(\DateTimeImmutable $newExpiresAt): void
    {
        if ($newExpiresAt > $this->expiresAt) {
            $this->expiresAt = $newExpiresAt;
        }
    }

    public function extendByDuration(\DateInterval $interval): void
    {
        $this->expiresAt = $this->expiresAt?->add($interval) ?? 
                          (new \DateTimeImmutable())->add($interval);
    }

    public function getRemainingLifetime(): int
    {
        if ($this->expiresAt === null || $this->isExpired()) {
            return 0;
        }

        return $this->expiresAt->getTimestamp() - time();
    }

    public function getDuration(): int
    {
        $endTime = $this->endedAt ?? new \DateTimeImmutable();
        return $endTime->getTimestamp() - $this->createdAt->getTimestamp();
    }

    public function getIdleTime(): int
    {
        if ($this->lastActivityAt === null) {
            return 0;
        }

        return time() - $this->lastActivityAt->getTimestamp();
    }

    public function isIdle(int $maxIdleSeconds = 1800): bool // 30 minutes default
    {
        return $this->getIdleTime() > $maxIdleSeconds;
    }

    public function hasIpChanged(): bool
    {
        return $this->lastIpChangeAt !== null;
    }

    public function isSuspicious(): bool
    {
        // Multiple IP changes
        if ($this->hasIpChanged() && $this->requestCount > 100) {
            return true;
        }

        // Too many requests in short time
        $duration = $this->getDuration();
        if ($duration < 300 && $this->requestCount > 50) { // 50 requests in 5 minutes
            return true;
        }

        return false;
    }

    public function setMetadata(array $metadata): void
    {
        $this->metadata = $metadata;
    }

    public function addMetadata(string $key, mixed $value): void
    {
        if ($this->metadata === null) {
            $this->metadata = [];
        }
        $this->metadata[$key] = $value;
    }

    public function getMetadataValue(string $key): mixed
    {
        return $this->metadata[$key] ?? null;
    }

    private function generateSessionId(): string
    {
        return 'sess_' . bin2hex(random_bytes(60)); // 128 characters total
    }

    public function toArray(): array
    {
        return [
            'id' => $this->id,
            'session_id' => $this->sessionId,
            'user_id' => $this->user->getId()->toString(),
            'username' => $this->user->getUsername(),
            'ip_address' => $this->ipAddress,
            'user_agent' => $this->userAgent,
            'created_at' => $this->createdAt->format(\DateTimeInterface::ATOM),
            'last_activity_at' => $this->lastActivityAt?->format(\DateTimeInterface::ATOM),
            'expires_at' => $this->expiresAt?->format(\DateTimeInterface::ATOM),
            'is_active' => $this->isActive,
            'ended_at' => $this->endedAt?->format(\DateTimeInterface::ATOM),
            'end_reason' => $this->endReason,
            'request_count' => $this->requestCount,
            'last_ip_change_at' => $this->lastIpChangeAt?->format(\DateTimeInterface::ATOM),
            'previous_ip_address' => $this->previousIpAddress,
            'metadata' => $this->metadata,
            'is_expired' => $this->isExpired(),
            'is_valid' => $this->isValid(),
            'remaining_lifetime' => $this->getRemainingLifetime(),
            'duration' => $this->getDuration(),
            'idle_time' => $this->getIdleTime(),
            'is_idle' => $this->isIdle(),
            'has_ip_changed' => $this->hasIpChanged(),
            'is_suspicious' => $this->isSuspicious(),
        ];
    }
} 