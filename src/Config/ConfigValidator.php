<?php

declare(strict_types=1);

namespace Senza1dio\SecurityShield\Config;

/**
 * Configuration Value Validator
 *
 * Validates configuration values against rules.
 *
 * USAGE:
 * ```php
 * $validator = ConfigValidator::create()
 *     ->type('integer')
 *     ->min(1)
 *     ->max(1000)
 *     ->required();
 *
 * $result = $validator->validate($value);
 * if (!$result->valid) {
 *     echo $result->error;
 * }
 * ```
 */
class ConfigValidator
{
    private bool $required = false;
    private ?string $type = null;
    private mixed $min = null;
    private mixed $max = null;
    private ?array $allowedValues = null;
    private ?string $pattern = null;
    /** @var callable|null */
    private mixed $customValidator = null;

    /**
     * Create new validator
     */
    public static function create(): self
    {
        return new self();
    }

    /**
     * Mark as required (cannot be null)
     */
    public function required(): self
    {
        $this->required = true;
        return $this;
    }

    /**
     * Set expected type
     *
     * @param string $type One of: string, integer, float, boolean, array
     */
    public function type(string $type): self
    {
        $this->type = $type;
        return $this;
    }

    /**
     * Set minimum value (for numbers) or length (for strings)
     */
    public function min(int|float $min): self
    {
        $this->min = $min;
        return $this;
    }

    /**
     * Set maximum value (for numbers) or length (for strings)
     */
    public function max(int|float $max): self
    {
        $this->max = $max;
        return $this;
    }

    /**
     * Set allowed values (enum)
     *
     * @param array<mixed> $values Allowed values
     */
    public function oneOf(array $values): self
    {
        $this->allowedValues = $values;
        return $this;
    }

    /**
     * Set regex pattern (for strings)
     *
     * @param string $pattern Valid PCRE regex pattern
     * @throws \InvalidArgumentException If pattern is invalid
     */
    public function pattern(string $pattern): self
    {
        // Validate the regex pattern
        if (@preg_match($pattern, '') === false) {
            $error = preg_last_error_msg();
            throw new \InvalidArgumentException("Invalid regex pattern '{$pattern}': {$error}");
        }

        $this->pattern = $pattern;
        return $this;
    }

    /**
     * Set custom validator function
     *
     * @param callable(mixed): bool|string $validator Returns true or error message
     */
    public function custom(callable $validator): self
    {
        $this->customValidator = $validator;
        return $this;
    }

    /**
     * Validate a value
     *
     * @param mixed $value Value to validate
     * @return ValidationResult
     */
    public function validate(mixed $value): ValidationResult
    {
        // Required check
        if ($this->required && $value === null) {
            return ValidationResult::invalid('Value is required');
        }

        // Null is OK if not required
        if ($value === null) {
            return ValidationResult::valid();
        }

        // Type check
        if ($this->type !== null) {
            $typeResult = $this->validateType($value);
            if (!$typeResult->valid) {
                return $typeResult;
            }
        }

        // Min/Max check
        if ($this->min !== null || $this->max !== null) {
            $rangeResult = $this->validateRange($value);
            if (!$rangeResult->valid) {
                return $rangeResult;
            }
        }

        // Allowed values check
        if ($this->allowedValues !== null) {
            if (!in_array($value, $this->allowedValues, true)) {
                $allowed = implode(', ', array_map(fn($v) => var_export($v, true), $this->allowedValues));
                return ValidationResult::invalid("Value must be one of: {$allowed}");
            }
        }

        // Pattern check
        if ($this->pattern !== null && is_string($value)) {
            if (!preg_match($this->pattern, $value)) {
                return ValidationResult::invalid("Value does not match pattern: {$this->pattern}");
            }
        }

        // Custom validator
        if ($this->customValidator !== null) {
            $result = ($this->customValidator)($value);
            if ($result !== true) {
                return ValidationResult::invalid(is_string($result) ? $result : 'Custom validation failed');
            }
        }

        return ValidationResult::valid();
    }

    private function validateType(mixed $value): ValidationResult
    {
        $valid = match ($this->type) {
            'string' => is_string($value),
            'integer', 'int' => is_int($value) || (is_string($value) && ctype_digit($value)),
            'float', 'double' => is_float($value) || is_int($value) || is_numeric($value),
            'boolean', 'bool' => is_bool($value) || in_array($value, ['true', 'false', '1', '0', 1, 0], true),
            'array' => is_array($value),
            default => true,
        };

        if (!$valid) {
            return ValidationResult::invalid("Expected type {$this->type}, got " . gettype($value));
        }

        return ValidationResult::valid();
    }

    private function validateRange(mixed $value): ValidationResult
    {
        if (is_string($value)) {
            $length = strlen($value);

            if ($this->min !== null && $length < $this->min) {
                return ValidationResult::invalid("String length must be at least {$this->min}");
            }

            if ($this->max !== null && $length > $this->max) {
                return ValidationResult::invalid("String length must be at most {$this->max}");
            }
        } elseif (is_numeric($value)) {
            if ($this->min !== null && $value < $this->min) {
                return ValidationResult::invalid("Value must be at least {$this->min}");
            }

            if ($this->max !== null && $value > $this->max) {
                return ValidationResult::invalid("Value must be at most {$this->max}");
            }
        } elseif (is_array($value)) {
            $count = count($value);

            if ($this->min !== null && $count < $this->min) {
                return ValidationResult::invalid("Array must have at least {$this->min} elements");
            }

            if ($this->max !== null && $count > $this->max) {
                return ValidationResult::invalid("Array must have at most {$this->max} elements");
            }
        }

        return ValidationResult::valid();
    }
}
