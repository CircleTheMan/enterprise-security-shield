# Enterprise Security Shield - Usage Examples

This directory contains comprehensive examples demonstrating all features of the security package.

## Quick Start

### Prerequisites

```bash
composer require senza1dio/enterprise-security-shield
```

**Requirements:**
- PHP 8.0+
- Redis 5.0+ (6.0+ recommended)
- ext-redis PHP extension
- ext-json PHP extension

### Basic Usage

```php
$redis = new Redis();
$redis->connect('127.0.0.1', 6379);

$storage = new RedisStorage($redis);
$config = new SecurityConfig();
$waf = new WafMiddleware($config, $storage);

if (!$waf->handle($_SERVER)) {
    http_response_code(403);
    die('Access Denied');
}
```

## Examples Overview

### 1. Basic Setup (`01-basic-setup.php`)
**Complexity:** Beginner
**Time:** 5 minutes
**Features:**
- Minimal configuration
- SQL injection protection
- XSS protection
- Path traversal protection
- Auto-blocking based on threat score

**Use Case:** Get started quickly with essential protection.

---

### 2. GeoIP Blocking (`02-geoip-blocking.php`)
**Complexity:** Intermediate
**Time:** 10 minutes
**Features:**
- Country-based blocking
- GeoIP lookup with caching
- Multi-provider fallback
- Proxy/VPN detection
- Datacenter IP detection

**Use Case:**
- Compliance (GDPR, data sovereignty)
- Block high-risk regions
- Region-specific content restrictions

**Example:**
```php
$config->setBlockedCountries(['CN', 'RU', 'KP']); // Block China, Russia, North Korea
```

---

### 3. Metrics & Monitoring (`03-metrics-monitoring.php`)
**Complexity:** Intermediate
**Time:** 15 minutes
**Features:**
- Real-time metrics collection
- Performance tracking
- Attack pattern analysis
- Block rate calculation
- Response time histograms

**Use Case:**
- Dashboard integration (Grafana, Datadog)
- Capacity planning
- Security analytics
- SLA monitoring

**Metrics Available:**
- `waf.requests.allowed` - Total allowed requests
- `waf.requests.blocked` - Total blocked requests
- `waf.blocked.{reason}` - Blocks by reason
- `waf.processing_time` - WAF processing latency

---

### 4. Webhook Alerts (`04-webhook-alerts.php`)
**Complexity:** Intermediate
**Time:** 10 minutes
**Features:**
- Real-time alerts to Slack/Discord
- Custom webhook endpoints
- Async sending (non-blocking)
- Event-driven notifications
- Severity levels

**Use Case:**
- Real-time security monitoring
- Incident response
- Team notifications
- SOC operations

**Supported Platforms:**
- Slack
- Discord
- PagerDuty
- Custom HTTP endpoints

---

### 5. Complete Enterprise Setup (`05-complete-enterprise.php`)
**Complexity:** Advanced
**Time:** 30 minutes
**Features:**
- Full WAF with all features
- GeoIP + Metrics + Webhooks
- Honeypot traps
- Rate limiting
- Trusted proxy support
- PSR-3 logging (Monolog)
- Production-grade configuration

**Use Case:** Enterprise production deployment with all security layers.

**Architecture:**
```
Internet
   ↓
Cloudflare/Proxy (trusted)
   ↓
Enterprise Security Shield
   ├─ WAF (threat detection)
   ├─ GeoIP (country blocking)
   ├─ Metrics (monitoring)
   ├─ Webhooks (alerting)
   └─ Rate Limiting
   ↓
Your Application
```

---

## Configuration Guide

### Threat Score Thresholds

```php
$config
    ->setAutoBlockThreshold(100)       // Auto-ban at 100 points
    ->setSQLInjectionThreshold(50)     // +50 for SQL injection
    ->setXSSThreshold(40)              // +40 for XSS
    ->setPathTraversalThreshold(45)    // +45 for path traversal
    ->setCommandInjectionThreshold(80); // +80 for command injection
```

**Example Attack Scenarios:**
- Single SQL injection attempt: 50 points (not banned yet)
- Two SQL injection attempts: 100 points (auto-banned)
- SQL injection + XSS: 90 points (not banned yet)
- Command injection: 80 points + any other attack = banned

### Rate Limiting

```php
$config
    ->setRateLimitEnabled(true)
    ->setRateLimitWindow(60)          // 60 seconds
    ->setRateLimitMaxRequests(100);   // 100 requests/minute
```

**Use Case:** Prevent brute force, scraping, DDoS attacks.

### Honeypot Traps

```php
$config
    ->setHoneypotEnabled(true)
    ->setHoneypotPaths([
        '/admin/config.php',           // Fake admin panel
        '/.env',                       // Environment file
        '/backup.sql',                 // Fake database backup
    ]);
```

**How it works:** Any access to these paths = instant ban (no legitimate user should access them).

### Trusted Proxies

```php
$config->setTrustedProxies([
    '173.245.48.0/20',  // Cloudflare
    '10.0.0.0/8',       // Internal network
]);
```

**Why needed:** Correctly identify real client IP behind proxies/load balancers.

---

## Integration Examples

### Laravel Middleware

```php
namespace App\Http\Middleware;

use Senza1dio\SecurityShield\Middleware\WafMiddleware;

class SecurityMiddleware
{
    private WafMiddleware $waf;

    public function handle($request, Closure $next)
    {
        if (!$this->waf->handle($_SERVER)) {
            abort(403, 'Access Denied');
        }

        return $next($request);
    }
}
```

### Symfony Event Listener

```php
use Symfony\Component\HttpKernel\Event\RequestEvent;

class WafListener
{
    public function onKernelRequest(RequestEvent $event)
    {
        if (!$this->waf->handle($_SERVER)) {
            throw new AccessDeniedHttpException('Access Denied');
        }
    }
}
```

### WordPress Plugin

```php
add_action('init', function() {
    $waf = getWafInstance(); // Your singleton

    if (!$waf->handle($_SERVER)) {
        wp_die('Access Denied', 403);
    }
});
```

---

## Performance Tips

### 1. Redis Connection Pooling

```php
// Use persistent connections
$redis->pconnect('127.0.0.1', 6379);
```

### 2. GeoIP Cache TTL

```php
// Balance between API limits and freshness
$geoipService->setCacheTTL(86400); // 24 hours (recommended)
```

### 3. Async Webhooks

```php
// Never block requests for webhook delivery
$webhooks->setAsync(true); // Default
```

### 4. Metrics Sampling

```php
// For ultra-high traffic, sample metrics
if (rand(1, 100) <= 10) { // 10% sampling
    $metrics->increment('waf.requests.allowed');
}
```

---

## Testing Examples

### Unit Testing

```php
use PHPUnit\Framework\TestCase;

class WafTest extends TestCase
{
    public function testBlocksSQLInjection()
    {
        $_SERVER['REQUEST_URI'] = "/user?id=1' OR '1'='1";

        $this->assertFalse($waf->handle($_SERVER));
        $this->assertEquals('sql_injection', $waf->getBlockReason());
    }
}
```

### Load Testing

```bash
# Apache Bench
ab -n 10000 -c 100 http://localhost/

# Expected performance:
# - <1ms WAF processing time (cache hit)
# - <5ms WAF processing time (cache miss)
# - 10,000+ requests/second on modern hardware
```

---

## Troubleshooting

### High False Positive Rate

```php
// Increase thresholds
$config
    ->setSQLInjectionThreshold(80)  // Was 50
    ->setAutoBlockThreshold(150);   // Was 100
```

### GeoIP Lookups Slow

```php
// Increase cache TTL
$geoipService->setCacheTTL(604800); // 7 days

// Or add faster provider as primary
$geoipService->addProvider(new MaxMindProvider($apiKey)); // Paid, faster
```

### Redis Memory Issues

```php
// Reduce retention
$config->setScoreTTL(300); // 5 minutes (was 15 minutes)

// Or enable Redis eviction
redis-cli CONFIG SET maxmemory-policy allkeys-lru
```

---

## Advanced Topics

### Custom Attack Patterns

```php
// Add custom regex patterns
$config->addCustomPattern('credit_card', '/\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b/', 60);
```

### Machine Learning Integration (Future)

```php
// Adaptive threat scoring based on historical data
$waf->enableAdaptiveLearning(true);
$waf->setLearningPeriod(86400); // 24 hours
```

### Multi-Region GeoIP

```php
// Use different providers per region
if ($clientCountry === 'US') {
    $geoipService->addProvider(new MaxMindProvider($apiKey));
} else {
    $geoipService->addProvider(new IPApiProvider());
}
```

---

## Support

- **Documentation:** https://github.com/senza1dio/enterprise-security-shield
- **Issues:** https://github.com/senza1dio/enterprise-security-shield/issues
- **Security:** security@example.com (for vulnerabilities)

---

## License

MIT License - See LICENSE file for details.
