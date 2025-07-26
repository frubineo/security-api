<?php

declare(strict_types=1);

namespace SecurityApi\Domain\ValueObject;

/**
 * Value Object pour les rôles utilisateur
 * 
 * Respecte la hiérarchie RBAC de l'écosystème
 */
final class UserRole
{
    public const USER = 'ROLE_USER';
    public const ANALYST = 'ROLE_ANALYST';
    public const SYSTEM = 'ROLE_SYSTEM';
    public const ADMIN = 'ROLE_ADMIN';
    public const SUPER_ADMIN = 'ROLE_SUPER_ADMIN';
    public const SECURITY = 'ROLE_SECURITY';

    private const VALID_ROLES = [
        self::USER,
        self::ANALYST,
        self::SYSTEM,
        self::ADMIN,
        self::SUPER_ADMIN,
        self::SECURITY,
    ];

    private const ROLE_HIERARCHY = [
        self::USER => [],
        self::ANALYST => [self::USER],
        self::SYSTEM => [self::USER],
        self::ADMIN => [self::USER, self::SYSTEM, self::ANALYST],
        self::SUPER_ADMIN => [self::ADMIN, self::USER, self::SYSTEM, self::ANALYST],
        self::SECURITY => [self::SUPER_ADMIN, self::ADMIN, self::USER, self::SYSTEM, self::ANALYST],
    ];

    private string $value;

    private function __construct(string $value)
    {
        $this->validate($value);
        $this->value = $value;
    }

    public static function user(): self
    {
        return new self(self::USER);
    }

    public static function analyst(): self
    {
        return new self(self::ANALYST);
    }

    public static function system(): self
    {
        return new self(self::SYSTEM);
    }

    public static function admin(): self
    {
        return new self(self::ADMIN);
    }

    public static function superAdmin(): self
    {
        return new self(self::SUPER_ADMIN);
    }

    public static function security(): self
    {
        return new self(self::SECURITY);
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

    public function hasRole(string $role): bool
    {
        // Check if current role is the exact role requested
        if ($this->value === $role) {
            return true;
        }

        // Check if current role inherits the requested role
        $inheritedRoles = self::ROLE_HIERARCHY[$this->value] ?? [];
        return in_array($role, $inheritedRoles, true);
    }

    public function getAllRoles(): array
    {
        $roles = [$this->value];
        $inheritedRoles = self::ROLE_HIERARCHY[$this->value] ?? [];
        
        return array_unique(array_merge($roles, $inheritedRoles));
    }

    public function isAdmin(): bool
    {
        return $this->hasRole(self::ADMIN);
    }

    public function isSuperAdmin(): bool
    {
        return $this->hasRole(self::SUPER_ADMIN);
    }

    public function isSecurityRole(): bool
    {
        return $this->hasRole(self::SECURITY);
    }

    public function canAccessAdminFunctions(): bool
    {
        return $this->isAdmin() || $this->isSuperAdmin() || $this->isSecurityRole();
    }

    public function canManageUsers(): bool
    {
        return $this->isSuperAdmin() || $this->isSecurityRole();
    }

    public function canManageSecurity(): bool
    {
        return $this->isSecurityRole();
    }

    public function getRoleLevel(): int
    {
        return match ($this->value) {
            self::USER => 1,
            self::ANALYST => 2,
            self::SYSTEM => 2,
            self::ADMIN => 3,
            self::SUPER_ADMIN => 4,
            self::SECURITY => 5,
            default => 0,
        };
    }

    public function isHigherThan(self $other): bool
    {
        return $this->getRoleLevel() > $other->getRoleLevel();
    }

    public function getDisplayName(): string
    {
        return match ($this->value) {
            self::USER => 'User',
            self::ANALYST => 'Analyst',
            self::SYSTEM => 'System',
            self::ADMIN => 'Administrator',
            self::SUPER_ADMIN => 'Super Administrator',
            self::SECURITY => 'Security Administrator',
            default => 'Unknown',
        };
    }

    private function validate(string $value): void
    {
        if (!in_array($value, self::VALID_ROLES, true)) {
            throw new \InvalidArgumentException(sprintf(
                'Invalid role "%s". Valid roles are: %s',
                $value,
                implode(', ', self::VALID_ROLES)
            ));
        }
    }
} 