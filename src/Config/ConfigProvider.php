<?php

declare(strict_types=1);

namespace Senza1dio\SecurityShield\Config;

use Senza1dio\SecurityShield\Contracts\StorageInterface;

/**
 * Enterprise Configuration Provider
 *
 * Multi-source configuration with hot-reload support.
 *
 * PRIORITY (highest to lowest):
 * 1. Runtime overrides (set via code)
 * 2. Environment variables
 * 3. Remote config (Redis/DB for hot-reload)
 * 4. File config (config.php, config.json)
 * 5. Default values
 *
 * HOT-RELOAD:
 * Remote config changes are picked up automatically without restart.
 * Cache TTL controls how often remote config is refreshed.
 *
 * USAGE:
 * ```php
 * $config = new ConfigProvider($storage, [
 *     'prefix' => 'security_shield:',
 *     'cache_ttl' => 60,
 *     'env_prefix' => 'SECURITY_SHIELD_',
 * ]);
 *
 * // Load defaults
 * $config->setDefaults([
 *     'score_threshold' => 50,
 *     'ban_duration' => 86400,
 * ]);
 *
 * // Get config value (checks all sources)
 * $threshold = $config->get('score_threshold');
 *
 * // Hot-reload: update in Redis, all instances pick it up
 * $config->setRemote('score_threshold', 100);
 * ```
 *
 * @package Senza1dio\SecurityShield\Config
 */
class ConfigProvider
{
    private ?StorageInterface $storage;
    private string $keyPrefix;
    private string $envPrefix;
    private int $cacheTTL;

    /** @var array<string, mixed> */
    private array $defaults = [];

    /** @var array<string, mixed> */
    private array $overrides = [];

    /** @var array<string, mixed> */
    private array $cache = [];

    private ?float $cacheLoadedAt = null;

    /** @var array<string, callable> */
    private array $changeListeners = [];

    /** @var array<string, ConfigValidator> */
    private array $validators = [];

    /**
     * @param StorageInterface|null $storage Remote storage for hot-reload
     * @param array{
     *     prefix?: string,
     *     cache_ttl?: int,
     *     env_prefix?: string
     * } $options Configuration options
     */
    public function __construct(?StorageInterface $storage = null, array $options = [])
    {
        $this->storage = $storage;
        $this->keyPrefix = $options['prefix'] ?? 'config:';
        $this->envPrefix = $options['env_prefix'] ?? '';
        $this->cacheTTL = $options['cache_ttl'] ?? 60;
    }

    // ==================== GETTERS ====================

    /**
     * Get configuration value
     *
     * @param string $key Configuration key
     * @param mixed $default Default if not found
     * @return mixed Configuration value
     */
    public function get(string $key, mixed $default = null): mixed
    {
        // 1. Runtime overrides (highest priority)
        if (array_key_exists($key, $this->overrides)) {
            return $this->overrides[$key];
        }

        // 2. Environment variables
        $envValue = $this->getFromEnv($key);
        if ($envValue !== null) {
            return $envValue;
        }

        // 3. Remote config (with caching)
        $remoteValue = $this->getFromRemote($key);
        if ($remoteValue !== null) {
            return $remoteValue;
        }

        // 4. Defaults
        if (array_key_exists($key, $this->defaults)) {
            return $this->defaults[$key];
        }

        return $default;
    }

    /**
     * Get integer configuration value
     */
    public function getInt(string $key, int $default = 0): int
    {
        $value = $this->get($key, $default);
        return is_numeric($value) ? (int) $value : $default;
    }

    /**
     * Get float configuration value
     */
    public function getFloat(string $key, float $default = 0.0): float
    {
        $value = $this->get($key, $default);
        return is_numeric($value) ? (float) $value : $default;
    }

    /**
     * Get boolean configuration value
     */
    public function getBool(string $key, bool $default = false): bool
    {
        $value = $this->get($key, $default);

        if (is_bool($value)) {
            return $value;
        }

        if (is_string($value)) {
            return in_array(strtolower($value), ['true', '1', 'yes', 'on'], true);
        }

        return (bool) $value;
    }

    /**
     * Get string configuration value
     */
    public function getString(string $key, string $default = ''): string
    {
        $value = $this->get($key, $default);
        return is_string($value) ? $value : $default;
    }

    /**
     * Get array configuration value
     *
     * @param string $key
     * @param array<mixed> $default
     * @return array<mixed>
     */
    public function getArray(string $key, array $default = []): array
    {
        $value = $this->get($key, $default);

        if (is_array($value)) {
            return $value;
        }

        if (is_string($value)) {
            $decoded = json_decode($value, true);
            return is_array($decoded) ? $decoded : $default;
        }

        return $default;
    }

    /**
     * Check if configuration key exists
     */
    public function has(string $key): bool
    {
        return $this->get($key) !== null;
    }

    // ==================== SETTERS ====================

    /**
     * Set runtime override (highest priority)
     *
     * @param string $key Configuration key
     * @param mixed $value Configuration value
     */
    public function set(string $key, mixed $value): self
    {
        $oldValue = $this->get($key);
        $this->overrides[$key] = $value;

        if ($oldValue !== $value) {
            $this->notifyListeners($key, $oldValue, $value);
        }

        return $this;
    }

    /**
     * Set remote configuration (hot-reloadable)
     *
     * @param string $key Configuration key
     * @param mixed $value Configuration value
     * @param int|null $ttl TTL in seconds (null = no expiry)
     */
    public function setRemote(string $key, mixed $value, ?int $ttl = null): self
    {
        if ($this->storage === null) {
            throw new \RuntimeException('No storage configured for remote config');
        }

        $oldValue = $this->get($key);

        $serialized = is_scalar($value) ? (string) $value : json_encode($value);
        $this->storage->set($this->keyPrefix . $key, $serialized, $ttl);

        // Invalidate cache
        unset($this->cache[$key]);

        if ($oldValue !== $value) {
            $this->notifyListeners($key, $oldValue, $value);
        }

        return $this;
    }

    /**
     * Set default values
     *
     * @param array<string, mixed> $defaults
     */
    public function setDefaults(array $defaults): self
    {
        $this->defaults = array_merge($this->defaults, $defaults);
        return $this;
    }

    /**
     * Remove runtime override
     */
    public function unset(string $key): self
    {
        unset($this->overrides[$key]);
        return $this;
    }

    /**
     * Remove remote configuration
     */
    public function deleteRemote(string $key): self
    {
        if ($this->storage !== null) {
            $this->storage->delete($this->keyPrefix . $key);
        }

        unset($this->cache[$key]);
        return $this;
    }

    // ==================== VALIDATION ====================

    /**
     * Add validator for a configuration key
     *
     * @param string $key Configuration key
     * @param ConfigValidator $validator Validator instance
     */
    public function addValidator(string $key, ConfigValidator $validator): self
    {
        $this->validators[$key] = $validator;
        return $this;
    }

    /**
     * Validate a configuration value
     *
     * @param string $key Configuration key
     * @param mixed $value Value to validate
     * @return ValidationResult Validation result
     */
    public function validate(string $key, mixed $value): ValidationResult
    {
        if (!isset($this->validators[$key])) {
            return ValidationResult::valid();
        }

        return $this->validators[$key]->validate($value);
    }

    /**
     * Validate all current configuration
     *
     * @return array<string, ValidationResult>
     */
    public function validateAll(): array
    {
        $results = [];

        foreach ($this->validators as $key => $validator) {
            $value = $this->get($key);
            $results[$key] = $validator->validate($value);
        }

        return $results;
    }

    // ==================== CHANGE LISTENERS ====================

    /**
     * Register listener for configuration changes
     *
     * @param string $key Configuration key (or '*' for all)
     * @param callable(string $key, mixed $oldValue, mixed $newValue): void $callback
     */
    public function onChange(string $key, callable $callback): self
    {
        $this->changeListeners[$key] = $callback;
        return $this;
    }

    // ==================== CACHE ====================

    /**
     * Clear configuration cache
     */
    public function clearCache(): self
    {
        $this->cache = [];
        $this->cacheLoadedAt = null;
        return $this;
    }

    /**
     * Refresh configuration from remote
     */
    public function refresh(): self
    {
        $this->clearCache();
        return $this;
    }

    // ==================== EXPORT/IMPORT ====================

    /**
     * Export all configuration
     *
     * @return array<string, mixed>
     */
    public function export(): array
    {
        $config = [];

        // Start with defaults
        foreach ($this->defaults as $key => $value) {
            $config[$key] = $this->get($key);
        }

        // Add any remote-only keys
        if ($this->storage !== null) {
            $this->loadRemoteCache();
            foreach ($this->cache as $key => $value) {
                if (!array_key_exists($key, $config)) {
                    $config[$key] = $value;
                }
            }
        }

        // Add overrides
        foreach ($this->overrides as $key => $value) {
            $config[$key] = $value;
        }

        return $config;
    }

    /**
     * Import configuration from array
     *
     * @param array<string, mixed> $config Configuration to import
     * @param bool $remote If true, set as remote config
     */
    public function import(array $config, bool $remote = false): self
    {
        foreach ($config as $key => $value) {
            if ($remote) {
                $this->setRemote($key, $value);
            } else {
                $this->set($key, $value);
            }
        }

        return $this;
    }

    // ==================== PRIVATE METHODS ====================

    private function getFromEnv(string $key): mixed
    {
        $envKey = $this->envPrefix . strtoupper(str_replace('.', '_', $key));
        $value = getenv($envKey);

        if ($value === false) {
            $value = $_ENV[$envKey] ?? null;
        }

        if ($value === false || $value === null) {
            return null;
        }

        return $value;
    }

    private function getFromRemote(string $key): mixed
    {
        if ($this->storage === null) {
            return null;
        }

        // Check if cache is stale
        if ($this->isCacheStale()) {
            $this->loadRemoteCache();
        }

        // Return from cache if available
        if (array_key_exists($key, $this->cache)) {
            return $this->cache[$key];
        }

        // Fallback: try to fetch individual key from storage
        $value = $this->storage->get($this->keyPrefix . $key);

        if ($value === null) {
            return null;
        }

        // Try to decode JSON, otherwise return raw value
        $decoded = is_string($value) ? json_decode($value, true) : null;
        $result = (json_last_error() === JSON_ERROR_NONE && $decoded !== null) ? $decoded : $value;

        // Cache the fetched value
        $this->cache[$key] = $result;

        return $result;
    }

    private function isCacheStale(): bool
    {
        if ($this->cacheLoadedAt === null) {
            return true;
        }

        return (microtime(true) - $this->cacheLoadedAt) >= $this->cacheTTL;
    }

    private function loadRemoteCache(): void
    {
        if ($this->storage === null) {
            return;
        }

        // Try to load config manifest (list of all known keys) if available
        $manifestKey = $this->keyPrefix . '_manifest';
        $manifest = $this->storage->get($manifestKey);

        if ($manifest !== null && is_string($manifest)) {
            $keys = json_decode($manifest, true);

            if (is_array($keys)) {
                foreach ($keys as $key) {
                    $value = $this->storage->get($this->keyPrefix . $key);

                    if ($value !== null) {
                        $decoded = is_string($value) ? json_decode($value, true) : null;
                        $this->cache[$key] = (json_last_error() === JSON_ERROR_NONE && $decoded !== null)
                            ? $decoded
                            : $value;
                    }
                }
            }
        }

        // Also try to load config blob (all config in single key) for efficiency
        $blobKey = $this->keyPrefix . '_blob';
        $blob = $this->storage->get($blobKey);

        if ($blob !== null && is_string($blob)) {
            $blobData = json_decode($blob, true);

            if (is_array($blobData)) {
                $this->cache = array_merge($this->cache, $blobData);
            }
        }

        $this->cacheLoadedAt = microtime(true);
    }

    private function notifyListeners(string $key, mixed $oldValue, mixed $newValue): void
    {
        // Notify specific key listener
        if (isset($this->changeListeners[$key])) {
            ($this->changeListeners[$key])($key, $oldValue, $newValue);
        }

        // Notify wildcard listener
        if (isset($this->changeListeners['*'])) {
            ($this->changeListeners['*'])($key, $oldValue, $newValue);
        }
    }
}
