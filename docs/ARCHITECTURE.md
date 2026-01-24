# Security Shield - Enterprise Architecture

## Overview

Security Shield provides enterprise-grade security middleware with resilience patterns, observability, and anomaly detection for PHP applications.

```
┌─────────────────────────────────────────────────────────────────────────┐
│                           Application Layer                              │
├─────────────────────────────────────────────────────────────────────────┤
│  SecurityMiddleware │ HoneypotMiddleware │ RateLimiter │ AnomalyDetector│
├─────────────────────────────────────────────────────────────────────────┤
│                           Resilience Layer                               │
│  CircuitBreaker │ RetryPolicy │ FallbackChain │ Bulkhead                │
├─────────────────────────────────────────────────────────────────────────┤
│                          Observability Layer                             │
│  Tracer (OpenTelemetry) │ Meter (Metrics) │ HealthCheck                 │
├─────────────────────────────────────────────────────────────────────────┤
│                         Configuration Layer                              │
│  ConfigProvider │ ConfigValidator │ Hot-Reload                          │
├─────────────────────────────────────────────────────────────────────────┤
│                           Storage Layer                                  │
│  RedisStorage │ MemoryStorage │ DatabaseStorage                         │
└─────────────────────────────────────────────────────────────────────────┘
```

## Components

### 1. Resilience Patterns

#### Circuit Breaker (`src/Resilience/CircuitBreaker.php`)

Prevents cascading failures by failing fast when a service is unavailable.

**States:**
- **CLOSED** - Normal operation, requests pass through
- **OPEN** - Service unavailable, requests fail immediately
- **HALF_OPEN** - Testing if service recovered

```php
$breaker = new CircuitBreaker($storage, 'external-api',
    failureThreshold: 5,
    recoveryTimeout: 30
);

$result = $breaker->call(
    fn() => $httpClient->get('/api/data'),
    fn() => $cache->get('fallback_data') // Fallback
);
```

#### Retry Policy (`src/Resilience/RetryPolicy.php`)

Handles transient failures with configurable retry strategies.

**Strategies:**
- **Exponential Backoff** - 1s, 2s, 4s, 8s...
- **Linear Backoff** - 1s, 2s, 3s, 4s...
- **Constant** - Fixed delay between retries
- **No Delay** - Immediate retries

```php
$policy = RetryPolicy::exponentialBackoffWithJitter(
    maxAttempts: 5,
    baseDelay: 1.0,
    maxDelay: 30.0
);

$result = $policy->execute(fn() => $api->call());
```

#### Fallback Chain (`src/Resilience/FallbackChain.php`)

Provides multi-provider failover with circuit breakers per provider.

```php
$chain = new FallbackChain($storage);

$chain->addProvider('primary', fn() => $primaryApi->get());
$chain->addProvider('secondary', fn() => $secondaryApi->get());
$chain->addProvider('cache', fn() => $cache->get('data'));

$result = $chain->execute();
```

#### Bulkhead (`src/Resilience/Bulkhead.php`)

Isolates resources to prevent resource exhaustion.

```php
$bulkhead = new Bulkhead('api-calls',
    maxConcurrent: 10,
    maxQueued: 50
);

$result = $bulkhead->execute(fn() => $api->call());
```

### 2. Rate Limiting

#### RateLimiter (`src/RateLimiting/RateLimiter.php`)

Multiple algorithms for different use cases:

**Algorithms:**
- **Sliding Window** - Smooth rate limiting
- **Token Bucket** - Allows bursts
- **Leaky Bucket** - Constant output rate
- **Fixed Window** - Simple counting

```php
// Per-second rate limiting with bursts
$limiter = RateLimiter::tokenBucket($storage,
    bucketSize: 100,
    tokensPerSecond: 10
);

$result = $limiter->attempt('user:123');
if (!$result->allowed) {
    throw new RateLimitException("Retry after {$result->retryAfter}s");
}
```

#### CompositeRateLimiter

Multi-tier rate limiting:

```php
$limiter = CompositeRateLimiter::create($storage, 'api')
    ->perSecond(10)
    ->perMinute(100)
    ->perHour(1000);
```

### 3. Health Checks

#### HealthCheck (`src/Health/HealthCheck.php`)

Kubernetes-compatible liveness/readiness probes.

```php
$health = new HealthCheck();

$health->addCheck('redis', new RedisHealthCheck($redis));
$health->addCheck('database', new DatabaseHealthCheck($pdo));

// Liveness probe (process alive)
$liveness = $health->liveness();

// Readiness probe (all dependencies healthy)
$readiness = $health->readiness();

echo $readiness->toJson();
```

**Response Format:**
```json
{
  "status": "healthy",
  "components": {
    "redis": { "status": "healthy", "message": "Connected" },
    "database": { "status": "healthy", "message": "Connected" }
  }
}
```

### 4. OpenTelemetry Integration

#### Tracer (`src/Telemetry/Tracer.php`)

Distributed tracing with W3C Trace Context propagation.

```php
$tracer = new Tracer('security-shield', '1.0.0');
$tracer->addExporter(new OtlpHttpExporter('http://collector:4318'));
$tracer->setSampler(new RatioBasedSampler(0.1)); // 10% sampling

// Trace a request
$span = $tracer->startSpan('http.request', SpanKind::SERVER);
$span->setAttribute('http.method', 'POST');

$childSpan = $tracer->startSpan('db.query');
// ... database operation
$childSpan->end();

$span->end();
$tracer->flush();
```

#### Metrics (`src/Telemetry/Metrics/Meter.php`)

OpenTelemetry-compatible metrics with Prometheus export.

```php
$meter = new Meter('security-shield');
$meter->addExporter(new PrometheusExporter('/metrics'));

// Counter
$requestCounter = $meter->createCounter('http_requests_total');
$requestCounter->increment(['method' => 'POST', 'status' => '200']);

// Histogram
$latencyHistogram = $meter->createHistogram('request_latency_seconds');
$latencyHistogram->record(0.125, ['endpoint' => '/api']);

// Prometheus format
echo $meter->toPrometheusFormat();
```

### 5. Configuration Management

#### ConfigProvider (`src/Config/ConfigProvider.php`)

Hot-reloadable configuration from multiple sources.

**Priority (highest to lowest):**
1. Runtime overrides
2. Environment variables
3. Remote config (Redis)
4. Default values

```php
$config = new ConfigProvider($storage, [
    'prefix' => 'security:config:',
    'cache_ttl' => 60,
    'env_prefix' => 'SECURITY_',
]);

$config->setDefaults([
    'score_threshold' => 50,
    'ban_duration' => 86400,
]);

// Get value (checks all sources)
$threshold = $config->getInt('score_threshold');

// Hot-reload: update in Redis
$config->setRemote('score_threshold', 100);

// Listen for changes
$config->onChange('score_threshold', function($key, $old, $new) {
    $logger->info("Config changed: {$key} = {$new}");
});
```

### 6. Anomaly Detection

#### AnomalyDetector (`src/Anomaly/AnomalyDetector.php`)

Multi-algorithm anomaly detection system.

**Detectors:**
- **StatisticalDetector** - Z-score, IQR outlier detection
- **RateDetector** - Request rate spikes/drops
- **PatternDetector** - Unusual request patterns
- **TimeBasedDetector** - Off-hours activity

```php
$detector = new AnomalyDetector();

$detector->addDetector(new StatisticalDetector(['request_count', 'latency']));
$detector->addDetector(new RateDetector($storage));
$detector->addDetector(new PatternDetector());
$detector->addDetector(new TimeBasedDetector('Europe/Rome'));

// Train with historical data
$detector->train($historicalData);

// Analyze request
$result = $detector->analyze([
    'request_count' => 500,
    'method' => 'POST',
    'path' => '/api/admin/delete',
    'timestamp' => time(),
]);

foreach ($result->getHigh() as $anomaly) {
    $logger->warning('Anomaly detected', $anomaly->toArray());
}
```

## Data Flow

### Request Processing

```
Request → RateLimiter → SecurityMiddleware → Application
             ↓                   ↓
         [blocked]         [threat score]
             ↓                   ↓
         Response          AnomalyDetector
                                 ↓
                            [anomaly?]
                                 ↓
                              Alert
```

### Resilience Flow

```
Client Request
      ↓
  Bulkhead (concurrency limit)
      ↓
  CircuitBreaker (fail fast)
      ↓
  RetryPolicy (transient failures)
      ↓
  FallbackChain (multi-provider)
      ↓
  Response
```

## Storage Layer

All components use `StorageInterface` for persistence:

```php
interface StorageInterface
{
    public function get(string $key): ?string;
    public function set(string $key, string $value, ?int $ttl = null): bool;
    public function delete(string $key): bool;
    public function exists(string $key): bool;
    public function increment(string $key, int $value = 1): int;
    public function decrement(string $key, int $value = 1): int;
}
```

**Implementations:**
- `RedisStorage` - Production (recommended)
- `MemoryStorage` - In-process caching
- `DatabaseStorage` - SQL persistence

## Kubernetes Integration

### Health Endpoints

```php
// In your controller
public function liveness(): Response
{
    $result = $this->healthCheck->liveness();
    return new JsonResponse(
        $result->toArray(),
        $result->isHealthy() ? 200 : 503
    );
}

public function readiness(): Response
{
    $result = $this->healthCheck->readiness();
    return new JsonResponse(
        $result->toArray(),
        $result->isHealthy() ? 200 : 503
    );
}
```

### Kubernetes Manifests

```yaml
livenessProbe:
  httpGet:
    path: /health/live
    port: 8080
  initialDelaySeconds: 10
  periodSeconds: 5

readinessProbe:
  httpGet:
    path: /health/ready
    port: 8080
  initialDelaySeconds: 5
  periodSeconds: 5
```

## Performance Considerations

### Caching
- Config caching with TTL
- DNS verification results cached 24h
- Rate limiter state in Redis

### Sampling
- Use `RatioBasedSampler` for high-traffic (10% sampling)
- Full sampling for errors and anomalies

### Bulkhead Sizing
```
maxConcurrent = (target_latency_ms * requests_per_second) / 1000
maxQueued = maxConcurrent * 5
```

## Security Best Practices

1. **Defense in Depth** - Use alongside real WAF
2. **Rate Limit Tiers** - Per-user, per-IP, global
3. **Honeypot Traps** - Detect reconnaissance
4. **Anomaly Alerts** - Real-time notification
5. **Circuit Breakers** - Prevent cascade failures

## Monitoring Checklist

- [ ] Health endpoints returning 200
- [ ] Prometheus metrics exposed
- [ ] Trace sampling configured
- [ ] Alert handlers registered
- [ ] Circuit breaker states monitored
- [ ] Rate limit violations logged
