<?php

declare(strict_types=1);

namespace SecurityApi\Domain\ValueObject;

/**
 * Value Object pour le statut utilisateur
 */
final class UserStatus
{
    public const ACTIVE = 'active';
    public const INACTIVE = 'inactive';
    public const SUSPENDED = 'suspended';
    public const PENDING_VERIFICATION = 'pending_verification';
    public const DELETED = 'deleted';

    private const VALID_STATUSES = [
        self::ACTIVE,
        self::INACTIVE,
        self::SUSPENDED,
        self::PENDING_VERIFICATION,
        self::DELETED,
    ];

    private string $value;

    private function __construct(string $value)
    {
        $this->validate($value);
        $this->value = $value;
    }

    public static function active(): self
    {
        return new self(self::ACTIVE);
    }

    public static function inactive(): self
    {
        return new self(self::INACTIVE);
    }

    public static function suspended(): self
    {
        return new self(self::SUSPENDED);
    }

    public static function pendingVerification(): self
    {
        return new self(self::PENDING_VERIFICATION);
    }

    public static function deleted(): self
    {
        return new self(self::DELETED);
    }

    public static function fromString(string $value): self
    {
        return new self($value);
    }

    public function getValue(): string
    {
        return $this->value;
    }

    public function toString(): string
    {
        return $this->value;
    }

    public function __toString(): string
    {
        return $this->toString();
    }

    public function equals(self $other): bool
    {
        return $this->value === $other->value;
    }

    public function isActive(): bool
    {
        return $this->value === self::ACTIVE;
    }

    public function isInactive(): bool
    {
        return $this->value === self::INACTIVE;
    }

    public function isSuspended(): bool
    {
        return $this->value === self::SUSPENDED;
    }

    public function isPendingVerification(): bool
    {
        return $this->value === self::PENDING_VERIFICATION;
    }

    public function isDeleted(): bool
    {
        return $this->value === self::DELETED;
    }

    public function canLogin(): bool
    {
        return $this->isActive();
    }

    public function canBeActivated(): bool
    {
        return in_array($this->value, [self::INACTIVE, self::SUSPENDED, self::PENDING_VERIFICATION], true);
    }

    public function getDisplayName(): string
    {
        return match ($this->value) {
            self::ACTIVE => 'Active',
            self::INACTIVE => 'Inactive',
            self::SUSPENDED => 'Suspended',
            self::PENDING_VERIFICATION => 'Pending Verification',
            self::DELETED => 'Deleted',
            default => 'Unknown',
        };
    }

    public function getColor(): string
    {
        return match ($this->value) {
            self::ACTIVE => 'green',
            self::INACTIVE => 'gray',
            self::SUSPENDED => 'red',
            self::PENDING_VERIFICATION => 'orange',
            self::DELETED => 'black',
            default => 'gray',
        };
    }

    private function validate(string $value): void
    {
        if (!in_array($value, self::VALID_STATUSES, true)) {
            throw new \InvalidArgumentException(sprintf(
                'Invalid status "%s". Valid statuses are: %s',
                $value,
                implode(', ', self::VALID_STATUSES)
            ));
        }
    }
} 