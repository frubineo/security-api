<?php

declare(strict_types=1);

namespace SecurityApi\Domain\ValueObject;

/**
 * Value Object pour l'email avec validation
 */
final class Email
{
    private string $value;

    private function __construct(string $value)
    {
        $this->validate($value);
        $this->value = strtolower($value);
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

    public function getDomain(): string
    {
        return substr($this->value, strpos($this->value, '@') + 1);
    }

    public function getLocalPart(): string
    {
        return substr($this->value, 0, strpos($this->value, '@'));
    }

    private function validate(string $value): void
    {
        if (empty($value)) {
            throw new \InvalidArgumentException('Email cannot be empty');
        }

        if (!filter_var($value, FILTER_VALIDATE_EMAIL)) {
            throw new \InvalidArgumentException(sprintf('Invalid email format: %s', $value));
        }

        if (strlen($value) > 320) { // RFC 5321 limit
            throw new \InvalidArgumentException('Email address too long (max 320 characters)');
        }

        // Additional security checks
        if (strpos($value, '..') !== false) {
            throw new \InvalidArgumentException('Email cannot contain consecutive dots');
        }

        // Prevent common security issues
        $domain = substr($value, strpos($value, '@') + 1);
        if (empty($domain) || strlen($domain) > 253) {
            throw new \InvalidArgumentException('Invalid email domain');
        }
    }
} 