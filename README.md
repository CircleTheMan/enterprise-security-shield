# Security Shield

[![PHP Version](https://img.shields.io/badge/PHP-%5E8.1-blue)](https://www.php.net/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

**Honeypot & Scanner Detection Middleware for PHP 8.1+**

Detects vulnerability scanners (sqlmap, nikto) and path probing (/.env, /.git). Framework-agnostic, zero dependencies.

---

## What This Is

- **Honeypot System** - Traps scanners probing /.env, /.git, /admin paths
- **Scanner Detection** - Identifies sqlmap, nikto, masscan by User-Agent
- **Rate Limiting** - IP-based request throttling
- **Bot Verification** - DNS validation for legitimate crawlers (Google, Bing)
- **Geo-Blocking** - Country-level IP restrictions (optional)

## What This Is NOT

- **Not a WAF** - No SQL injection or XSS detection
- **Not DDoS Protection** - Use Cloudflare/AWS Shield for that
- **Not Zero-Day Protection** - No ML, no behavioral analysis

**For actual WAF**: Use ModSecurity, Cloudflare WAF, or AWS WAF alongside this.

---

## Quick Start

```bash
composer require senza1dio/security-shield
```

```php
<?php
use Senza1dio\SecurityShield\Middleware\SecurityMiddleware;
use Senza1dio\SecurityShield\Config\SecurityConfig;
use Senza1dio\SecurityShield\Storage\RedisStorage;
use Senza1dio\SecurityShield\Storage\NullLogger;

// Connect Redis
$redis = new Redis();
$redis->connect('127.0.0.1', 6379);

// Create middleware
$storage = new RedisStorage($redis);
$config = (new SecurityConfig())
    ->setStorage($storage)
    ->setLogger(new NullLogger());

$security = new SecurityMiddleware($config);

// Protect your app
if (!$security->handle($_SERVER)) {
    http_response_code(403);
    exit('Access Denied');
}
```

---

## Features

### Threat Scoring
- Accumulates points for suspicious behavior
- Auto-ban at configurable threshold (default: 50 points)
- Critical paths: +30 points (/.env, /.git)
- Scanner User-Agents: +30 points (sqlmap, nikto)
- Empty User-Agent: +100 points (instant ban)

### Honeypot Traps
50+ trap endpoints including:
- `/.env`, `/.git/config`, `/.aws/credentials`
- `/phpinfo.php`, `/admin.php`, `/wp-admin`
- `/backup.sql`, `/dump.sql`

### Bot Verification
- DNS reverse/forward lookup for Google, Bing, Yandex
- IP range verification for OpenAI bots (ChatGPT-User, GPTBot)
- 24-hour cache to minimize DNS lookups

### Storage Backends
- **RedisStorage** - Production recommended
- **NullStorage** - Development/testing

---

## Configuration

```php
$config = (new SecurityConfig())
    ->setScoreThreshold(50)           // Auto-ban threshold
    ->setBanDuration(86400)           // 24 hours
    ->setTrackingWindow(3600)         // 1 hour
    ->enableHoneypot(true)
    ->enableBotVerification(true)
    ->addIPWhitelist(['127.0.0.1'])
    ->addIPBlacklist(['1.2.3.4'])
    ->setStorage($storage)
    ->setLogger($logger);
```

---

## Framework Integration

### Laravel

```php
// app/Http/Middleware/SecurityShield.php
namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Senza1dio\SecurityShield\Middleware\SecurityMiddleware;
use Senza1dio\SecurityShield\Config\SecurityConfig;
use Senza1dio\SecurityShield\Storage\RedisStorage;

class SecurityShield
{
    public function handle(Request $request, Closure $next)
    {
        $redis = app('redis')->connection()->client();
        $storage = new RedisStorage($redis);

        $config = (new SecurityConfig())->setStorage($storage);
        $security = new SecurityMiddleware($config);

        if (!$security->handle($request->server->all())) {
            abort(403);
        }

        return $next($request);
    }
}
```

### Symfony

```php
// src/EventListener/SecurityShieldListener.php
namespace App\EventListener;

use Symfony\Component\HttpKernel\Event\RequestEvent;
use Senza1dio\SecurityShield\Middleware\SecurityMiddleware;
use Senza1dio\SecurityShield\Config\SecurityConfig;
use Senza1dio\SecurityShield\Storage\RedisStorage;

class SecurityShieldListener
{
    public function onKernelRequest(RequestEvent $event): void
    {
        if (!$event->isMainRequest()) return;

        $redis = new \Redis();
        $redis->connect('127.0.0.1', 6379);

        $config = (new SecurityConfig())->setStorage(new RedisStorage($redis));
        $security = new SecurityMiddleware($config);

        if (!$security->handle($event->getRequest()->server->all())) {
            throw new \Symfony\Component\HttpKernel\Exception\AccessDeniedHttpException();
        }
    }
}
```

---

## Honeypot Usage

```php
use Senza1dio\SecurityShield\Middleware\HoneypotMiddleware;
use Senza1dio\SecurityShield\Exceptions\HoneypotAccessException;

$honeypot = new HoneypotMiddleware($config);

try {
    $honeypot->handle($_SERVER);
} catch (HoneypotAccessException $e) {
    // Attacker hit honeypot - send fake response
    echo $e->getResponse();
    exit;
}
```

---

## Requirements

- PHP 8.1+
- ext-json

### Optional
- ext-redis (for RedisStorage)
- ext-pdo (for DatabaseStorage)

---

## Testing

```bash
composer install
composer test      # PHPUnit
composer stan      # PHPStan level 5
```

---

## License

MIT License - see [LICENSE](LICENSE)

---

## Limitations

This package blocks known scanner patterns. It does NOT:
- Parse request bodies for SQL injection
- Detect XSS in responses
- Provide behavioral analysis
- Protect against zero-day attacks

Use this as a **pre-filter** alongside a real WAF for defense-in-depth.
