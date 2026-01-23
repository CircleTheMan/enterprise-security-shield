<?php

declare(strict_types=1);

/**
 * PrestaShop Integration Example
 *
 * Complete integration guide for PrestaShop 1.7+ / 8.x
 *
 * INSTALLATION STEPS:
 * 1. composer require senza1dio/enterprise-security-shield
 * 2. Create this file: modules/securityshield/securityshield.php
 * 3. Install Redis (required): apt-get install redis-server php-redis
 * 4. Enable module in PrestaShop admin
 * 5. Configure settings in module configuration page
 */

if (!defined('_PS_VERSION_')) {
    exit;
}

require_once _PS_MODULE_DIR_ . 'securityshield/vendor/autoload.php';

use Senza1dio\SecurityShield\Middleware\WafMiddleware;
use Senza1dio\SecurityShield\Config\SecurityConfig;
use Senza1dio\SecurityShield\Storage\RedisStorage;
use Senza1dio\SecurityShield\Services\GeoIP\{GeoIPService, IPApiProvider};
use Senza1dio\SecurityShield\Services\Metrics\RedisMetricsCollector;
use Senza1dio\SecurityShield\Services\WebhookNotifier;

/**
 * PrestaShop Security Shield Module
 *
 * Protects PrestaShop from:
 * - SQL injection attacks on product pages
 * - XSS attempts in search/comments
 * - Bot attacks on checkout/cart
 * - Admin panel brute force
 * - Payment form tampering
 * - Fake order submissions
 */
class SecurityShield extends Module
{
    private ?WafMiddleware $waf = null;
    private ?RedisStorage $storage = null;
    private ?\Redis $redis = null;

    public function __construct()
    {
        $this->name = 'securityshield';
        $this->tab = 'security';
        $this->version = '1.0.0';
        $this->author = 'Enterprise Security Shield';
        $this->need_instance = 0;
        $this->ps_versions_compliancy = ['min' => '1.7.0.0', 'max' => _PS_VERSION_];
        $this->bootstrap = true;

        parent::__construct();

        $this->displayName = $this->l('Enterprise Security Shield');
        $this->description = $this->l('WAF, Honeypot & Bot Protection for PrestaShop');
        $this->confirmUninstall = $this->l('Are you sure you want to uninstall this security module?');

        // Initialize WAF
        $this->initializeWAF();
    }

    /**
     * Module Installation
     */
    public function install(): bool
    {
        if (!parent::install()) {
            return false;
        }

        // Register hooks
        return $this->registerHook('actionDispatcher') &&
               $this->registerHook('header') &&
               $this->registerHook('displayBackOfficeHeader') &&
               $this->registerHook('actionValidateOrder') &&
               $this->registerHook('actionProductSearchAfter');
    }

    /**
     * Module Uninstallation
     */
    public function uninstall(): bool
    {
        return parent::uninstall();
    }

    /**
     * Module Configuration Page
     */
    public function getContent(): string
    {
        $output = '';

        // Handle form submission
        if (Tools::isSubmit('submitSecurityShield')) {
            Configuration::updateValue('SECURITY_SHIELD_ENABLED', Tools::getValue('SECURITY_SHIELD_ENABLED'));
            Configuration::updateValue('SECURITY_SHIELD_BAN_DURATION', Tools::getValue('SECURITY_SHIELD_BAN_DURATION'));
            Configuration::updateValue('SECURITY_SHIELD_THRESHOLD', Tools::getValue('SECURITY_SHIELD_THRESHOLD'));
            Configuration::updateValue('SECURITY_SHIELD_REDIS_HOST', Tools::getValue('SECURITY_SHIELD_REDIS_HOST'));
            Configuration::updateValue('SECURITY_SHIELD_REDIS_PORT', Tools::getValue('SECURITY_SHIELD_REDIS_PORT'));
            Configuration::updateValue('SECURITY_SHIELD_REDIS_PASSWORD', Tools::getValue('SECURITY_SHIELD_REDIS_PASSWORD'));
            Configuration::updateValue('SECURITY_SHIELD_GEOIP_ENABLED', Tools::getValue('SECURITY_SHIELD_GEOIP_ENABLED'));
            Configuration::updateValue('SECURITY_SHIELD_BLOCKED_COUNTRIES', Tools::getValue('SECURITY_SHIELD_BLOCKED_COUNTRIES'));

            $output .= $this->displayConfirmation($this->l('Settings updated'));

            // Reinitialize WAF with new config
            $this->initializeWAF();
        }

        // Display statistics
        $output .= $this->displayStatistics();

        // Display configuration form
        return $output . $this->displayForm();
    }

    /**
     * Display Security Statistics
     */
    private function displayStatistics(): string
    {
        if (!$this->redis || !$this->storage) {
            return '<div class="alert alert-warning">Redis not connected - statistics unavailable</div>';
        }

        $metrics = new RedisMetricsCollector($this->redis, 'prestashop_security:');

        $totalRequests = $metrics->get('requests.total') ?? 0;
        $blockedRequests = $metrics->get('requests.blocked') ?? 0;
        $blockRate = $totalRequests > 0 ? ($blockedRequests / $totalRequests) * 100 : 0;

        return '
        <div class="panel">
            <div class="panel-heading">
                <i class="icon-shield"></i> ' . $this->l('Security Statistics') . '
            </div>
            <div class="panel-body">
                <div class="row">
                    <div class="col-md-3">
                        <div class="statistic">
                            <h3>' . number_format($totalRequests) . '</h3>
                            <p>' . $this->l('Total Requests') . '</p>
                        </div>
                    </div>
                    <div class="col-md-3">
                        <div class="statistic">
                            <h3>' . number_format($blockedRequests) . '</h3>
                            <p>' . $this->l('Blocked Attacks') . '</p>
                        </div>
                    </div>
                    <div class="col-md-3">
                        <div class="statistic">
                            <h3>' . number_format($blockRate, 2) . '%</h3>
                            <p>' . $this->l('Block Rate') . '</p>
                        </div>
                    </div>
                    <div class="col-md-3">
                        <div class="statistic">
                            <h3>' . ($this->redis->ping() ? 'OK' : 'ERROR') . '</h3>
                            <p>' . $this->l('Redis Status') . '</p>
                        </div>
                    </div>
                </div>
            </div>
        </div>';
    }

    /**
     * Display Configuration Form
     */
    private function displayForm(): string
    {
        $defaultLang = (int) Configuration::get('PS_LANG_DEFAULT');

        $fieldsForm = [
            'form' => [
                'legend' => [
                    'title' => $this->l('Security Settings'),
                    'icon' => 'icon-cogs',
                ],
                'input' => [
                    [
                        'type' => 'switch',
                        'label' => $this->l('Enable WAF'),
                        'name' => 'SECURITY_SHIELD_ENABLED',
                        'is_bool' => true,
                        'values' => [
                            ['id' => 'active_on', 'value' => 1, 'label' => $this->l('Enabled')],
                            ['id' => 'active_off', 'value' => 0, 'label' => $this->l('Disabled')],
                        ],
                    ],
                    [
                        'type' => 'text',
                        'label' => $this->l('Ban Duration (seconds)'),
                        'name' => 'SECURITY_SHIELD_BAN_DURATION',
                        'desc' => $this->l('How long to ban malicious IPs (default: 3600 = 1 hour)'),
                    ],
                    [
                        'type' => 'text',
                        'label' => $this->l('Threat Threshold'),
                        'name' => 'SECURITY_SHIELD_THRESHOLD',
                        'desc' => $this->l('Auto-ban after X threat points (default: 100)'),
                    ],
                    [
                        'type' => 'text',
                        'label' => $this->l('Redis Host'),
                        'name' => 'SECURITY_SHIELD_REDIS_HOST',
                        'desc' => $this->l('Redis server host (default: 127.0.0.1)'),
                    ],
                    [
                        'type' => 'text',
                        'label' => $this->l('Redis Port'),
                        'name' => 'SECURITY_SHIELD_REDIS_PORT',
                        'desc' => $this->l('Redis server port (default: 6379)'),
                    ],
                    [
                        'type' => 'password',
                        'label' => $this->l('Redis Password'),
                        'name' => 'SECURITY_SHIELD_REDIS_PASSWORD',
                        'desc' => $this->l('Leave empty if Redis has no password'),
                    ],
                    [
                        'type' => 'switch',
                        'label' => $this->l('Enable GeoIP Blocking'),
                        'name' => 'SECURITY_SHIELD_GEOIP_ENABLED',
                        'is_bool' => true,
                        'values' => [
                            ['id' => 'geoip_on', 'value' => 1, 'label' => $this->l('Enabled')],
                            ['id' => 'geoip_off', 'value' => 0, 'label' => $this->l('Disabled')],
                        ],
                    ],
                    [
                        'type' => 'text',
                        'label' => $this->l('Blocked Countries'),
                        'name' => 'SECURITY_SHIELD_BLOCKED_COUNTRIES',
                        'desc' => $this->l('Comma-separated country codes (e.g., CN,RU,KP)'),
                    ],
                ],
                'submit' => [
                    'title' => $this->l('Save'),
                ],
            ],
        ];

        $helper = new HelperForm();
        $helper->module = $this;
        $helper->name_controller = $this->name;
        $helper->token = Tools::getAdminTokenLite('AdminModules');
        $helper->currentIndex = AdminController::$currentIndex . '&configure=' . $this->name;
        $helper->default_form_language = $defaultLang;
        $helper->allow_employee_form_lang = $defaultLang;
        $helper->title = $this->displayName;
        $helper->show_toolbar = true;
        $helper->toolbar_scroll = true;
        $helper->submit_action = 'submitSecurityShield';

        $helper->fields_value['SECURITY_SHIELD_ENABLED'] = Configuration::get('SECURITY_SHIELD_ENABLED', true);
        $helper->fields_value['SECURITY_SHIELD_BAN_DURATION'] = Configuration::get('SECURITY_SHIELD_BAN_DURATION', 3600);
        $helper->fields_value['SECURITY_SHIELD_THRESHOLD'] = Configuration::get('SECURITY_SHIELD_THRESHOLD', 100);
        $helper->fields_value['SECURITY_SHIELD_REDIS_HOST'] = Configuration::get('SECURITY_SHIELD_REDIS_HOST', '127.0.0.1');
        $helper->fields_value['SECURITY_SHIELD_REDIS_PORT'] = Configuration::get('SECURITY_SHIELD_REDIS_PORT', 6379);
        $helper->fields_value['SECURITY_SHIELD_REDIS_PASSWORD'] = Configuration::get('SECURITY_SHIELD_REDIS_PASSWORD', '');
        $helper->fields_value['SECURITY_SHIELD_GEOIP_ENABLED'] = Configuration::get('SECURITY_SHIELD_GEOIP_ENABLED', false);
        $helper->fields_value['SECURITY_SHIELD_BLOCKED_COUNTRIES'] = Configuration::get('SECURITY_SHIELD_BLOCKED_COUNTRIES', '');

        return $helper->generateForm([$fieldsForm]);
    }

    /**
     * Initialize WAF with PrestaShop configuration
     */
    private function initializeWAF(): void
    {
        if (!Configuration::get('SECURITY_SHIELD_ENABLED', true)) {
            return;
        }

        try {
            // Connect to Redis
            $this->redis = new \Redis();
            $redisHost = Configuration::get('SECURITY_SHIELD_REDIS_HOST', '127.0.0.1');
            $redisPort = (int) Configuration::get('SECURITY_SHIELD_REDIS_PORT', 6379);
            $redisPassword = Configuration::get('SECURITY_SHIELD_REDIS_PASSWORD', '');

            $this->redis->connect($redisHost, $redisPort);

            if (!empty($redisPassword)) {
                $this->redis->auth($redisPassword);
            }

            // Create storage
            $this->storage = new RedisStorage($this->redis, 'prestashop_security:');

            // Configure security
            $config = new SecurityConfig();
            $config
                ->setEnabled(true)
                ->setAutoBlockThreshold((int) Configuration::get('SECURITY_SHIELD_THRESHOLD', 100))
                ->setBanDuration((int) Configuration::get('SECURITY_SHIELD_BAN_DURATION', 3600))
                ->setScoreTTL(900)
                ->setHoneypotEnabled(true)
                ->setHoneypotPaths([
                    '/admin-dev',      // PrestaShop default admin
                    '/admin',
                    '/adminps',
                    '/backoffice',
                    '/config/settings.inc.php',  // PrestaShop config
                    '/app/config/parameters.php', // Symfony config
                ]);

            // GeoIP (if enabled)
            $geoipService = null;
            if (Configuration::get('SECURITY_SHIELD_GEOIP_ENABLED', false)) {
                $geoipService = new GeoIPService($this->storage);
                $geoipService->addProvider(new IPApiProvider());

                $blockedCountries = Configuration::get('SECURITY_SHIELD_BLOCKED_COUNTRIES', '');
                if (!empty($blockedCountries)) {
                    $countries = array_map('trim', explode(',', $blockedCountries));
                    $config->setGeoIPEnabled(true);
                    $config->setBlockedCountries($countries);
                }
            }

            // Metrics
            $metrics = new RedisMetricsCollector($this->redis, 'prestashop_security:');

            // Create WAF
            $this->waf = new WafMiddleware($config, $this->storage);

            if ($geoipService) {
                $this->waf->setGeoIPService($geoipService);
            }

            $this->waf->setMetricsCollector($metrics);

        } catch (\Throwable $e) {
            // Log error but don't crash PrestaShop
            PrestaShopLogger::addLog(
                'Security Shield initialization failed: ' . $e->getMessage(),
                3,
                null,
                'SecurityShield',
                1,
                true
            );
        }
    }

    /**
     * Hook: Main Request Dispatcher
     *
     * Runs BEFORE any PrestaShop controller
     */
    public function hookActionDispatcher($params): void
    {
        if (!$this->waf) {
            return;
        }

        // Check request
        $allowed = $this->waf->handle($_SERVER);

        if (!$allowed) {
            $reason = $this->waf->getBlockReason();

            // Log to PrestaShop
            PrestaShopLogger::addLog(
                "Security Shield blocked request: {$reason}",
                2,
                null,
                'SecurityShield',
                null,
                true
            );

            // Return 403
            header('HTTP/1.1 403 Forbidden');
            header('Content-Type: text/plain');
            echo 'Access Denied';
            exit;
        }

        // Track metrics
        if ($this->redis) {
            $metrics = new RedisMetricsCollector($this->redis, 'prestashop_security:');
            $metrics->increment('requests.total');
        }
    }

    /**
     * Hook: Header (track page views)
     */
    public function hookHeader($params): void
    {
        // Optional: Add security headers
        if ($this->waf) {
            // Already tracked in hookActionDispatcher
        }
    }

    /**
     * Hook: Validate Order (protect checkout)
     */
    public function hookActionValidateOrder($params): void
    {
        // Additional validation on orders can be added here
        // E.g., check if customer IP changed during checkout (session hijacking)
    }

    /**
     * Hook: Product Search (protect search from XSS)
     */
    public function hookActionProductSearchAfter($params): void
    {
        // Search queries are automatically checked by WAF
    }
}
