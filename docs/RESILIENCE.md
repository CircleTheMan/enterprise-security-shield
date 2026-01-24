# Resilience Patterns Guide

This guide covers the enterprise resilience patterns implemented in Security Shield.

## Circuit Breaker

The Circuit Breaker pattern prevents cascading failures by failing fast when a downstream service is unavailable.

### States

```
        success
    ┌──────────────┐
    │              ▼
┌───────┐     ┌─────────┐     failure     ┌────────┐
│CLOSED │────▶│HALF_OPEN│◀───────────────▶│  OPEN  │
└───────┘     └─────────┘   threshold     └────────┘
    ▲              │                           │
    │              │ success                   │
    │              ▼                           │
    └──────────────┴───────────────────────────┘
                    recovery timeout
```

### Configuration

```php
$breaker = new CircuitBreaker(
    $storage,
    'external-api',
    failureThreshold: 5,      // Open after 5 failures
    recoveryTimeout: 30,      // Wait 30s before trying again
    halfOpenMaxRequests: 3    // Allow 3 test requests in half-open
);
```

### Usage

```php
try {
    $result = $breaker->call(
        fn() => $httpClient->get('/api/data'),       // Primary operation
        fn() => $cache->get('fallback_data')         // Fallback
    );
} catch (CircuitOpenException $e) {
    // Circuit is open, fallback returned or exception thrown
    $logger->warning('Circuit open for: ' . $e->getCircuitName());
}
```

### Monitoring

```php
$stats = $breaker->getStats();
// [
//     'state' => 'closed',
//     'failure_count' => 2,
//     'failure_threshold' => 5,
//     'last_failure_time' => 1704110400.123
// ]
```

## Retry Policy

Handles transient failures with intelligent retry strategies.

### Strategies

#### Exponential Backoff with Jitter

Best for high-concurrency scenarios. Jitter prevents thundering herd.

```php
$policy = RetryPolicy::exponentialBackoffWithJitter(
    maxAttempts: 5,
    baseDelay: 1.0,
    maxDelay: 30.0,
    jitterFactor: 0.5  // ±50% randomization
);

// Delays: ~1s, ~2s, ~4s, ~8s, ~16s (with jitter)
```

#### Linear Backoff

Predictable, gradual increase.

```php
$policy = RetryPolicy::linearBackoff(
    maxAttempts: 5,
    initialDelay: 1.0,
    increment: 2.0
);

// Delays: 1s, 3s, 5s, 7s, 9s
```

#### Constant Delay

Simple fixed delay between retries.

```php
$policy = RetryPolicy::constant(
    maxAttempts: 3,
    delay: 5.0
);

// Delays: 5s, 5s
```

### Retry Conditions

```php
$policy = RetryPolicy::exponentialBackoff(3)
    // Only retry on specific exceptions
    ->retryOn(\Psr\Http\Client\NetworkExceptionInterface::class)

    // Custom condition
    ->retryWhen(fn(\Throwable $e) =>
        $e->getCode() >= 500 || str_contains($e->getMessage(), 'timeout')
    )

    // Callback on each retry
    ->onRetry(function(int $attempt, \Throwable $e) {
        $this->logger->warning("Retry {$attempt}: {$e->getMessage()}");
    });
```

### Best Practices

1. **Set sensible maximums** - Don't retry forever
2. **Use jitter** - Prevent thundering herd
3. **Cap delays** - `maxDelay` prevents extremely long waits
4. **Filter exceptions** - Only retry transient failures

## Fallback Chain

Multi-provider failover with per-provider circuit breakers.

### Configuration

```php
$chain = new FallbackChain($storage, 'data-service');

$chain->addProvider('primary',
    fn() => $primaryApi->get(),
    ['failureThreshold' => 3, 'recoveryTimeout' => 30]
);

$chain->addProvider('secondary',
    fn() => $secondaryApi->get(),
    ['failureThreshold' => 5, 'recoveryTimeout' => 60]
);

$chain->addProvider('cache',
    fn() => $cache->get('data'),
    null  // No circuit breaker for cache
);
```

### Execution

```php
try {
    $result = $chain->execute();
} catch (AllProvidersFailedException $e) {
    // All providers failed
    $logger->error('All providers failed', [
        'failures' => $e->getFailures()
    ]);
}
```

### Provider Status

```php
$status = $chain->getProviderStatus();
// [
//     'primary' => 'open',      // Circuit open
//     'secondary' => 'closed',  // OK
//     'cache' => 'closed'       // OK
// ]
```

## Bulkhead

Isolates resources to prevent resource exhaustion.

### Configuration

```php
$bulkhead = new Bulkhead(
    'api-calls',
    maxConcurrent: 10,   // Max 10 concurrent executions
    maxQueued: 50,       // Max 50 waiting in queue
    timeout: 5.0         // 5s timeout for queued items
);
```

### Usage

```php
try {
    $result = $bulkhead->execute(fn() => $api->call());
} catch (BulkheadFullException $e) {
    // Both slots and queue are full
    throw new ServiceUnavailableException('Service overloaded');
} catch (BulkheadTimeoutException $e) {
    // Waited in queue too long
    throw new ServiceUnavailableException('Request timeout');
}
```

### Sizing Guide

```
Target: 100ms average latency, 50 requests/second

maxConcurrent = 50 * 0.1 = 5 slots
maxQueued = 5 * 5 = 25 queued

With 200ms latency:
maxConcurrent = 50 * 0.2 = 10 slots
maxQueued = 10 * 5 = 50 queued
```

## Combining Patterns

### Full Protection Stack

```php
// Create components
$circuitBreaker = new CircuitBreaker($storage, 'api', 5, 30);
$retryPolicy = RetryPolicy::exponentialBackoffWithJitter(3);
$bulkhead = new Bulkhead('api', 10, 50);

// Execute with full protection
$result = $bulkhead->execute(function() use ($circuitBreaker, $retryPolicy) {
    return $retryPolicy->execute(function() use ($circuitBreaker) {
        return $circuitBreaker->call(
            fn() => $this->api->call(),
            fn() => $this->cache->get('fallback')
        );
    });
});
```

### Recommended Order

```
Request
    ↓
Bulkhead (limit concurrency)
    ↓
Circuit Breaker (fail fast)
    ↓
Retry Policy (handle transients)
    ↓
Fallback Chain (multi-provider)
    ↓
Response
```

## Anti-Patterns to Avoid

### 1. Retry Everything

```php
// BAD - retries 4xx client errors
$policy->execute(fn() => $api->call());

// GOOD - only retry server errors
$policy->retryWhen(fn($e) => $e->getCode() >= 500);
```

### 2. No Backoff

```php
// BAD - hammers service immediately
$policy = RetryPolicy::noDelay(10);

// GOOD - gives service time to recover
$policy = RetryPolicy::exponentialBackoff(10);
```

### 3. Infinite Retries

```php
// BAD - can retry forever
$policy = RetryPolicy::constant(PHP_INT_MAX, 1);

// GOOD - bounded retries
$policy = RetryPolicy::constant(5, 1);
```

### 4. Missing Fallback

```php
// BAD - throws when circuit opens
$breaker->call(fn() => $api->call());

// GOOD - graceful degradation
$breaker->call(
    fn() => $api->call(),
    fn() => $cache->get('data') ?? []
);
```

## Metrics & Monitoring

Track these metrics for resilience:

```php
// Circuit breaker events
- circuit_breaker_state_changes_total{circuit="api", from="closed", to="open"}
- circuit_breaker_failures_total{circuit="api"}
- circuit_breaker_successes_total{circuit="api"}

// Retry metrics
- retry_attempts_total{policy="api"}
- retry_successes_total{policy="api", attempt="3"}

// Bulkhead metrics
- bulkhead_active_count{name="api"}
- bulkhead_queued_count{name="api"}
- bulkhead_rejected_total{name="api"}
```
