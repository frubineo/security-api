<?php

declare(strict_types=1);

namespace SecurityApi\Domain\Entity;

use Doctrine\ORM\Mapping as ORM;
use Ramsey\Uuid\Uuid;

/**
 * Entité pour l'audit de sécurité centralisé
 * 
 * Enregistre toutes les actions de sécurité critiques
 */
#[ORM\Entity]
#[ORM\Table(name: 'security_audit_logs')]
#[ORM\Index(columns: ['user_id'], name: 'idx_audit_user')]
#[ORM\Index(columns: ['event_type'], name: 'idx_audit_event_type')]
#[ORM\Index(columns: ['occurred_at'], name: 'idx_audit_date')]
#[ORM\Index(columns: ['severity'], name: 'idx_audit_severity')]
#[ORM\Index(columns: ['ip_address'], name: 'idx_audit_ip')]
class SecurityAuditLog
{
    public const SEVERITY_LOW = 'low';
    public const SEVERITY_MEDIUM = 'medium';
    public const SEVERITY_HIGH = 'high';
    public const SEVERITY_CRITICAL = 'critical';

    public const EVENT_LOGIN_SUCCESS = 'login.success';
    public const EVENT_LOGIN_FAILED = 'login.failed';
    public const EVENT_LOGIN_BLOCKED = 'login.blocked';
    public const EVENT_PASSWORD_CHANGED = 'password.changed';
    public const EVENT_MFA_ENABLED = 'mfa.enabled';
    public const EVENT_MFA_DISABLED = 'mfa.disabled';
    public const EVENT_API_KEY_GENERATED = 'api_key.generated';
    public const EVENT_API_KEY_REVOKED = 'api_key.revoked';
    public const EVENT_TOKEN_ISSUED = 'token.issued';
    public const EVENT_TOKEN_REVOKED = 'token.revoked';
    public const EVENT_ACCOUNT_LOCKED = 'account.locked';
    public const EVENT_ACCOUNT_UNLOCKED = 'account.unlocked';
    public const EVENT_ROLE_CHANGED = 'role.changed';
    public const EVENT_PERMISSION_DENIED = 'permission.denied';
    public const EVENT_INTRUSION_DETECTED = 'intrusion.detected';
    public const EVENT_SUSPICIOUS_ACTIVITY = 'suspicious.activity';

    #[ORM\Id]
    #[ORM\Column(type: 'uuid')]
    private string $id;

    #[ORM\ManyToOne(targetEntity: User::class, inversedBy: 'auditLogs')]
    #[ORM\JoinColumn(name: 'user_id', referencedColumnName: 'id', nullable: true)]
    private ?User $user = null;

    #[ORM\Column(type: 'string', length: 100)]
    private string $eventType;

    #[ORM\Column(type: 'string', length: 20)]
    private string $severity;

    #[ORM\Column(type: 'text')]
    private string $description;

    #[ORM\Column(type: 'string', length: 45)]
    private string $ipAddress;

    #[ORM\Column(type: 'text', nullable: true)]
    private ?string $userAgent = null;

    #[ORM\Column(type: 'datetime_immutable')]
    private \DateTimeImmutable $occurredAt;

    #[ORM\Column(type: 'string', length: 255, nullable: true)]
    private ?string $resource = null;

    #[ORM\Column(type: 'string', length: 100, nullable: true)]
    private ?string $action = null;

    #[ORM\Column(type: 'json', nullable: true)]
    private ?array $context = null;

    #[ORM\Column(type: 'json', nullable: true)]
    private ?array $oldValues = null;

    #[ORM\Column(type: 'json', nullable: true)]
    private ?array $newValues = null;

    #[ORM\Column(type: 'string', length: 100, nullable: true)]
    private ?string $sourceService = null;

    #[ORM\Column(type: 'string', length: 255, nullable: true)]
    private ?string $requestId = null;

    #[ORM\Column(type: 'boolean', options: ['default' => false])]
    private bool $isAlert = false;

    #[ORM\Column(type: 'boolean', options: ['default' => false])]
    private bool $isResolved = false;

    #[ORM\Column(type: 'datetime_immutable', nullable: true)]
    private ?\DateTimeImmutable $resolvedAt = null;

    #[ORM\Column(type: 'string', length: 255, nullable: true)]
    private ?string $resolvedBy = null;

    public function __construct(
        string $eventType,
        string $severity,
        string $description,
        string $ipAddress,
        ?User $user = null,
        ?string $userAgent = null,
        ?string $resource = null,
        ?string $action = null,
        ?array $context = null,
        ?array $oldValues = null,
        ?array $newValues = null,
        ?string $sourceService = null,
        ?string $requestId = null
    ) {
        $this->id = Uuid::uuid4()->toString();
        $this->eventType = $eventType;
        $this->severity = $severity;
        $this->description = $description;
        $this->ipAddress = $ipAddress;
        $this->user = $user;
        $this->userAgent = $userAgent;
        $this->resource = $resource;
        $this->action = $action;
        $this->context = $context;
        $this->oldValues = $oldValues;
        $this->newValues = $newValues;
        $this->sourceService = $sourceService;
        $this->requestId = $requestId;
        $this->occurredAt = new \DateTimeImmutable();
        $this->isAlert = in_array($severity, [self::SEVERITY_HIGH, self::SEVERITY_CRITICAL], true);
    }

    // Getters
    public function getId(): string
    {
        return $this->id;
    }

    public function getUser(): ?User
    {
        return $this->user;
    }

    public function getEventType(): string
    {
        return $this->eventType;
    }

    public function getSeverity(): string
    {
        return $this->severity;
    }

    public function getDescription(): string
    {
        return $this->description;
    }

    public function getIpAddress(): string
    {
        return $this->ipAddress;
    }

    public function getUserAgent(): ?string
    {
        return $this->userAgent;
    }

    public function getOccurredAt(): \DateTimeImmutable
    {
        return $this->occurredAt;
    }

    public function getResource(): ?string
    {
        return $this->resource;
    }

    public function getAction(): ?string
    {
        return $this->action;
    }

    public function getContext(): ?array
    {
        return $this->context;
    }

    public function getOldValues(): ?array
    {
        return $this->oldValues;
    }

    public function getNewValues(): ?array
    {
        return $this->newValues;
    }

    public function getSourceService(): ?string
    {
        return $this->sourceService;
    }

    public function getRequestId(): ?string
    {
        return $this->requestId;
    }

    public function isAlert(): bool
    {
        return $this->isAlert;
    }

    public function isResolved(): bool
    {
        return $this->isResolved;
    }

    public function getResolvedAt(): ?\DateTimeImmutable
    {
        return $this->resolvedAt;
    }

    public function getResolvedBy(): ?string
    {
        return $this->resolvedBy;
    }

    // Business Methods
    public function isCritical(): bool
    {
        return $this->severity === self::SEVERITY_CRITICAL;
    }

    public function isHigh(): bool
    {
        return $this->severity === self::SEVERITY_HIGH;
    }

    public function isMedium(): bool
    {
        return $this->severity === self::SEVERITY_MEDIUM;
    }

    public function isLow(): bool
    {
        return $this->severity === self::SEVERITY_LOW;
    }

    public function resolve(?string $resolvedBy = null): void
    {
        $this->isResolved = true;
        $this->resolvedAt = new \DateTimeImmutable();
        $this->resolvedBy = $resolvedBy;
    }

    public function markAsAlert(): void
    {
        $this->isAlert = true;
    }

    public function addContext(string $key, mixed $value): void
    {
        if ($this->context === null) {
            $this->context = [];
        }
        $this->context[$key] = $value;
    }

    public function getContextValue(string $key): mixed
    {
        return $this->context[$key] ?? null;
    }

    public function getAge(): \DateInterval
    {
        return $this->occurredAt->diff(new \DateTimeImmutable());
    }

    public function isRecent(int $seconds = 300): bool
    {
        $age = (new \DateTimeImmutable())->getTimestamp() - $this->occurredAt->getTimestamp();
        return $age <= $seconds;
    }

    public function getSeverityLevel(): int
    {
        return match ($this->severity) {
            self::SEVERITY_LOW => 1,
            self::SEVERITY_MEDIUM => 2,
            self::SEVERITY_HIGH => 3,
            self::SEVERITY_CRITICAL => 4,
            default => 0,
        };
    }

    public static function createLoginSuccess(User $user, string $ipAddress, ?string $userAgent = null): self
    {
        return new self(
            eventType: self::EVENT_LOGIN_SUCCESS,
            severity: self::SEVERITY_LOW,
            description: sprintf('User %s successfully logged in', $user->getUsername()),
            ipAddress: $ipAddress,
            user: $user,
            userAgent: $userAgent,
            action: 'login'
        );
    }

    public static function createLoginFailed(string $username, string $ipAddress, ?string $userAgent = null, ?string $reason = null): self
    {
        return new self(
            eventType: self::EVENT_LOGIN_FAILED,
            severity: self::SEVERITY_MEDIUM,
            description: sprintf('Failed login attempt for user %s%s', $username, $reason ? ": $reason" : ''),
            ipAddress: $ipAddress,
            userAgent: $userAgent,
            action: 'login',
            context: ['username' => $username, 'reason' => $reason]
        );
    }

    public static function createIntrusionDetected(string $description, string $ipAddress, ?string $userAgent = null, ?array $context = null): self
    {
        return new self(
            eventType: self::EVENT_INTRUSION_DETECTED,
            severity: self::SEVERITY_CRITICAL,
            description: $description,
            ipAddress: $ipAddress,
            userAgent: $userAgent,
            context: $context
        );
    }

    public function toArray(): array
    {
        return [
            'id' => $this->id,
            'user_id' => $this->user?->getId()->toString(),
            'username' => $this->user?->getUsername(),
            'event_type' => $this->eventType,
            'severity' => $this->severity,
            'severity_level' => $this->getSeverityLevel(),
            'description' => $this->description,
            'ip_address' => $this->ipAddress,
            'user_agent' => $this->userAgent,
            'occurred_at' => $this->occurredAt->format(\DateTimeInterface::ATOM),
            'resource' => $this->resource,
            'action' => $this->action,
            'context' => $this->context,
            'old_values' => $this->oldValues,
            'new_values' => $this->newValues,
            'source_service' => $this->sourceService,
            'request_id' => $this->requestId,
            'is_alert' => $this->isAlert,
            'is_resolved' => $this->isResolved,
            'resolved_at' => $this->resolvedAt?->format(\DateTimeInterface::ATOM),
            'resolved_by' => $this->resolvedBy,
            'age_seconds' => (new \DateTimeImmutable())->getTimestamp() - $this->occurredAt->getTimestamp(),
        ];
    }
} 