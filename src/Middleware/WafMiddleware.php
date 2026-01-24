<?php

declare(strict_types=1);

namespace Senza1dio\SecurityShield\Middleware;

/**
 * WafMiddleware - Backward Compatibility Alias
 *
 * @deprecated Use SecurityMiddleware instead. This class will be removed in v3.0.
 * @see SecurityMiddleware
 */
class_alias(SecurityMiddleware::class, 'Senza1dio\SecurityShield\Middleware\WafMiddleware');
