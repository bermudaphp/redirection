<?php

namespace Bermuda\Http\Middleware;

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Container\ContainerInterface;

/**
 * HTTP Redirect Middleware
 *
 * Provides HTTP redirection functionality within the middleware stack with flexible
 * conditional logic. Supports both static verifiers (defined at middleware creation)
 * and dynamic verifiers (extracted from request attributes).
 *
 * This middleware can act as both a middleware component (allowing requests
 * to continue if conditions aren't met) and as a terminal request handler
 * (always performing the redirect).
 *
 * Features:
 * - Conditional redirects using custom verifier functions (closures, invokable objects, etc.)
 * - Dynamic verifier extraction from request attributes
 * - Support for permanent (301) and temporary (302) redirects
 * - Flexible callable support with automatic conversion to Closure
 * - Lazy instantiation through dependency injection containers
 * - Pre-built verifier factory for common redirect scenarios (Verifiers::*)
 *
 * Verifier Priority:
 * 1. Static verifier provided in constructor (highest priority)
 * 2. Dynamic verifier from request attributes (fallback)
 * 3. No verifier = always redirect (default behavior)
 *
 * Common Verifier Factory:
 * The Verifiers static class provides pre-built verifier functions for the most
 * common redirect scenarios including maintenance mode, HTTPS enforcement,
 * mobile detection, time windows, path matching, authentication checks, and more.
 *
 * Verifier Function:
 * The verifier accepts any callable type (closures, invokable objects, functions)
 * and automatically converts them to Closure internally for consistent handling.
 * The verifier receives the ServerRequestInterface and should return a boolean
 * indicating whether the redirect should occur.
 *
 * Common Verifier Examples:
 *
 * @example Maintenance Mode
 * $verifier = function(ServerRequestInterface $request): bool {
 *     return file_exists('/app/maintenance.flag');
 * };
 * // Or using factory:
 * $verifier = RedirectMiddleware::Verifiers::maintenanceMode('/app/maintenance.flag');
 *
 * @example HTTPS Enforcement
 * $verifier = function(ServerRequestInterface $request): bool {
 *     return $request->getUri()->getScheme() === 'http';
 * };
 * // Or using factory:
 * $verifier = RedirectMiddleware::Verifiers::forceHttps();
 *
 * @example Time-based Redirects
 * $verifier = function(ServerRequestInterface $request): bool {
 *     $hour = (int) date('H');
 *     return $hour >= 22 || $hour < 6; // Redirect during night hours
 * };
 * // Or using factory:
 * $verifier = RedirectMiddleware::Verifiers::timeWindow(22, 6);
 *
 * @example Path-based Redirects
 * $verifier = function(ServerRequestInterface $request): bool {
 *     $path = $request->getUri()->getPath();
 *     return str_starts_with($path, '/old/') || str_starts_with($path, '/deprecated/');
 * };
 * // Or using factory:
 * $verifier = RedirectMiddleware::Verifiers::pathMatches(['/old/', '/deprecated/']);
 *
 * @example User Agent Detection
 * $verifier = function(ServerRequestInterface $request): bool {
 *     $userAgent = $request->getHeaderLine('User-Agent');
 *     return str_contains($userAgent, 'mobile') || str_contains($userAgent, 'Mobile');
 * };
 * // Or using factory:
 * $verifier = RedirectMiddleware::Verifiers::mobileDevice();
 *
 * @example Feature Flag Based
 * $verifier = function(ServerRequestInterface $request): bool {
 *     $featureFlags = $request->getAttribute('feature_flags', []);
 *     return $featureFlags['new_site_enabled'] ?? false;
 * };
 * // Or using factory:
 * $verifier = RedirectMiddleware::Verifiers::featureFlag('new_site_enabled');
 *
 * @example Method-specific Redirects
 * $verifier = function(ServerRequestInterface $request): bool {
 *     return in_array($request->getMethod(), ['POST', 'PUT', 'DELETE']);
 * };
 * // Or using factory:
 * $verifier = RedirectMiddleware::Verifiers::httpMethods(['POST', 'PUT', 'DELETE']);
 *
 * @example IP-based Redirects
 * $verifier = function(ServerRequestInterface $request): bool {
 *     $clientIp = $request->getAttribute('client_ip');
 *     $blockedIps = ['192.168.1.100', '10.0.0.50'];
 *     return in_array($clientIp, $blockedIps);
 * };
 * // Or using factory:
 * $verifier = RedirectMiddleware::Verifiers::ipMatches(['192.168.1.100', '10.0.0.50']);
 *
 * @example Authentication Required
 * // Or using factory:
 * $verifier = RedirectMiddleware::Verifiers::requireAuth('user');
 *
 * @example Query Parameter Based
 * // Or using factory:
 * $verifier = RedirectMiddleware::Verifiers::queryParam('mobile', '1');
 *
 * @example Header Based
 * // Or using factory:
 * $verifier = RedirectMiddleware::Verifiers::header('X-API-Version', 'v2');
 *
 * @example Combined Verifiers
 * // Redirect if it's maintenance time AND user is not admin
 * $verifier = RedirectMiddleware::Verifiers::combine([
 *     RedirectMiddleware::Verifiers::timeWindow(2, 4),
 *     fn($req) => !$req->getAttribute('user')?->isAdmin()
 * ], false); // AND logic
 *
 * @example Dynamic Verifier via Request Attributes
 * // Set verifier in previous middleware
 * $request = $request->withAttribute(RedirectMiddleware::VERIFIER_ATTRIBUTE, 
 *     fn($req) => $req->getAttribute('maintenance_mode', false)
 * );
 */
final class RedirectMiddleware implements MiddlewareInterface, RequestHandlerInterface
{
    /**
     * Request attribute key for dynamic verifier functions.
     *
     * When no static verifier is provided in the constructor, the middleware
     * will look for a verifier function in the request attributes using this key.
     * This allows for dynamic, request-specific redirect logic.
     *
     * @var string
     */
    public const string VERIFIER_ATTRIBUTE = 'redirect.verifier';

    /**
     * Internal verifier closure for conditional redirect logic.
     *
     * Stores the verifier function as a Closure after conversion from any callable type.
     * This ensures consistent internal handling regardless of the original callable format.
     * When null, the middleware will attempt to extract a verifier from request attributes.
     *
     * @var \Closure|null The converted verifier function or null for dynamic extraction
     */
    private readonly ?\Closure $verifier;

    /**
     * Initialize the redirect middleware with configuration.
     *
     * Accepts any callable type for the verifier (closures, invokable objects, function names, etc.)
     * and automatically converts them to Closure for internal use. This provides maximum
     * flexibility while maintaining type safety and consistent behavior.
     *
     * When verifier is null, the middleware will attempt to extract a verifier function
     * from the request attributes using the VERIFIER_ATTRIBUTE key during processing.
     *
     * @param string $location Target URL for the redirect
     * @param ResponseFactoryInterface $responseFactory Factory for creating HTTP responses
     * @param callable|null $verifier Optional condition checker for conditional redirects
     *                                 Can be any callable: closure, invokable object, function name, etc.
     *                                 Receives ServerRequestInterface, returns bool
     *                                 If null, will attempt dynamic extraction from request attributes
     * @param bool $isPermanent Whether to send permanent (301) or temporary (302) redirect
     */
    public function __construct(
        private readonly string $location,
        private readonly ResponseFactoryInterface $responseFactory,
        callable $verifier = null,
        public readonly bool $isPermanent = false
    ) {
        // Convert any callable to Closure for consistent internal handling
        $this->verifier = $verifier ? static fn(ServerRequestInterface $request): bool => $verifier($request) : null;
    }

    /**
     * Process the request through the middleware stack.
     *
     * Evaluates the verifier condition to determine whether to redirect or continue processing.
     * The verifier evaluation follows this priority order:
     *
     * 1. Static verifier (provided in constructor) - highest priority
     * 2. Dynamic verifier (from request attributes) - fallback option
     * 3. No verifier found - always redirect (default behavior)
     *
     * Processing Logic:
     * - If verifier exists and returns true → redirect to configured location
     * - If verifier exists and returns false → continue to next handler in chain
     * - If no verifier (static or dynamic) → always redirect
     *
     * Dynamic Verifier Extraction:
     * When no static verifier is provided, the middleware attempts to extract
     * a verifier function from request attributes using VERIFIER_ATTRIBUTE key.
     * This enables request-specific redirect logic set by previous middleware.
     *
     * @param ServerRequestInterface $request The HTTP request to process
     * @param RequestHandlerInterface $handler The next handler in the middleware chain
     * @return ResponseInterface Either a redirect response or response from the next handler
     */
    public function process(
        ServerRequestInterface $request,
        RequestHandlerInterface $handler
    ): ResponseInterface {
        $verifier = $this->verifier;

        // If no static verifier, try to extract from request attributes
        if ($verifier === null) {
            $dynamicVerifier = $request->getAttribute(self::VERIFIER_ATTRIBUTE);
            if ($dynamicVerifier && is_callable($dynamicVerifier)) {
                $verifier = static fn(ServerRequestInterface $req): bool => $dynamicVerifier($req);
            }
        }

        // Evaluate verifier condition
        if ($verifier === null || $verifier($request)) {
            return $this->handle($request);
        }

        return $handler->handle($request);
    }

    /**
     * Handle the request by creating a redirect response.
     *
     * Always creates and returns a redirect response to the configured location,
     * regardless of any verifier conditions. This method is useful when the
     * middleware is used as a terminal request handler rather than a conditional middleware.
     *
     * HTTP Status Codes:
     * - 301 (Moved Permanently): For permanent redirects (SEO-friendly, cached by browsers)
     * - 302 (Found/Temporary Redirect): For temporary redirects (not cached, can change)
     *
     * @param ServerRequestInterface $request The HTTP request (not used but required by interface)
     * @return ResponseInterface HTTP redirect response with Location header set
     */
    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        return $this->responseFactory
            ->createResponse($this->isPermanent ? 301 : 302)
            ->withHeader('Location', $this->location);
    }

    /**
     * Create a lazy factory for dependency injection containers.
     *
     * Returns a factory function that can be used with dependency injection
     * containers to create RedirectMiddleware instances with resolved dependencies.
     * The ResponseFactoryInterface is automatically resolved from the container
     * when the factory is invoked.
     *
     * This approach enables:
     * - Lazy instantiation (middleware created only when needed)
     * - Automatic dependency resolution from DI containers
     * - Configuration reuse across multiple container instances
     * - Support for any callable verifier type with automatic Closure conversion
     *
     * @param string $location Target URL for the redirect
     * @param callable|null $verifier Condition checker function for conditional redirects
     *                               Can be any callable: closure, invokable object, etc.
     *                               If null, will use dynamic extraction from request attributes
     * @param bool|null $permanent Whether to create permanent (301) or temporary (302) redirects
     * @return callable Factory function that accepts a container and returns RedirectMiddleware
     *
     * @example Static Verifier with DI Container
     * // Register with DI container using factory verifier
     * $container->set('maintenance.redirect', RedirectMiddleware::lazy(
     *     '/maintenance',
     *     RedirectMiddleware::Verifiers::maintenanceMode('/app/maintenance.flag'),
     *     false
     * ));
     *
     * @example HTTPS Enforcement
     * $container->set('https.redirect', RedirectMiddleware::lazy(
     *     'https://secure.example.com',
     *     RedirectMiddleware::Verifiers::forceHttps(),
     *     true // Permanent redirect for SEO
     * ));
     *
     * @example Mobile Device Redirect
     * $container->set('mobile.redirect', RedirectMiddleware::lazy(
     *     'https://m.example.com',
     *     RedirectMiddleware::Verifiers::mobileDevice()
     * ));
     *
     * @example Dynamic Verifier with Request Attributes
     * // Register without verifier for dynamic extraction
     * $container->set('dynamic.redirect', RedirectMiddleware::lazy('/fallback'));
     * 
     * // Set verifier in previous middleware
     * $request = $request->withAttribute(RedirectMiddleware::VERIFIER_ATTRIBUTE,
     *     RedirectMiddleware::Verifiers::featureFlag('beta_site')
     * );
     *
     * @example Time-based Maintenance Window
     * $container->set('maintenance.window', RedirectMiddleware::lazy(
     *     '/maintenance',
     *     RedirectMiddleware::Verifiers::timeWindow(2, 4, 'America/New_York') // 2 AM - 4 AM EST
     * ));
     *
     * @example Path-based Legacy Redirects
     * $container->set('legacy.redirect', RedirectMiddleware::lazy(
     *     '/new-api',
     *     RedirectMiddleware::Verifiers::pathMatches(['/api/v1/', '/old-api/']),
     *     true // Permanent redirect for old APIs
     * ));
     *
     * @example Combined Conditions
     * $container->set('complex.redirect', RedirectMiddleware::lazy(
     *     '/restricted',
     *     RedirectMiddleware::Verifiers::combine([
     *         RedirectMiddleware::Verifiers::timeWindow(18, 9), // 6 PM to 9 AM
     *         RedirectMiddleware::Verifiers::requireAuth() // AND user not authenticated
     *     ], false) // AND logic
     * ));
     */
    public static function lazy(
        string $location,
        callable $verifier = null,
        ?bool $permanent = false
    ): callable {
        return static fn(ContainerInterface $container): self =>
        new self(
            $location,
            $container->get(ResponseFactoryInterface::class),
            $verifier ? \Closure::fromCallable($verifier) : null,
            $permanent
        );
    }

    /**
     * Create a request with dynamic verifier for use in middleware chain.
     *
     * Utility method to set a verifier function as a request attribute,
     * enabling dynamic redirect logic in downstream RedirectMiddleware instances.
     *
     * @param ServerRequestInterface $request The request to modify
     * @param callable $verifier The verifier function to attach
     * @return ServerRequestInterface New request instance with verifier attribute
     *
     * @example Setting Dynamic Verifier in Middleware Chain
     * // In an earlier middleware
     * $verifier = fn($req) => $req->getAttribute('user')->isBlocked();
     * $request = RedirectMiddleware::withVerifier($request, $verifier);
     * 
     * // Later RedirectMiddleware will use this verifier if it has no static verifier
     */
    public static function withVerifier(ServerRequestInterface $request, callable $verifier): ServerRequestInterface
    {
        return $request->withAttribute(self::VERIFIER_ATTRIBUTE, $verifier);
    }

    // ===== VERIFIER FACTORY METHODS =====

    /**
     * Maintenance mode verifier - redirects when maintenance flag file exists.
     *
     * @param string $flagFile Path to maintenance flag file
     * @return \Closure Verifier function that checks file existence
     *
     * @example
     * $verifier = RedirectMiddleware::maintenanceMode('/app/maintenance.flag');
     * $middleware = new RedirectMiddleware('/maintenance', $responseFactory, $verifier);
     */
    public static function maintenanceMode(string $flagFile): \Closure
    {
        return static fn(ServerRequestInterface $request): bool => file_exists($flagFile);
    }

    /**
     * HTTPS enforcement verifier - redirects HTTP requests to HTTPS.
     *
     * @return \Closure Verifier function that checks for HTTP scheme
     *
     * @example
     * $verifier = RedirectMiddleware::forceHttps();
     * $middleware = new RedirectMiddleware('https://secure.example.com', $responseFactory, $verifier, true);
     */
    public static function forceHttps(): \Closure
    {
        return static fn(ServerRequestInterface $request): bool => 
            $request->getUri()->getScheme() === 'http';
    }

    /**
     * Mobile device detection verifier - redirects mobile devices.
     *
     * @param array<string> $mobileKeywords Keywords to detect in User-Agent header
     * @return \Closure Verifier function that checks User-Agent for mobile indicators
     *
     * @example
     * $verifier = RedirectMiddleware::mobileDevice();
     * $middleware = new RedirectMiddleware('https://m.example.com', $responseFactory, $verifier);
     */
    public static function mobileDevice(array $mobileKeywords = ['Mobile', 'Android', 'iPhone', 'iPad']): \Closure
    {
        return static function(ServerRequestInterface $request) use ($mobileKeywords): bool {
            $userAgent = $request->getHeaderLine('User-Agent');
            foreach ($mobileKeywords as $keyword) {
                if (str_contains($userAgent, $keyword)) {
                    return true;
                }
            }
            return false;
        };
    }

    /**
     * Time-based verifier - redirects during specified time periods.
     *
     * @param int $startHour Start hour (0-23)
     * @param int $endHour End hour (0-23)
     * @param string $timezone Timezone for time calculation
     * @return \Closure Verifier function that checks current time
     *
     * @example
     * // Maintenance window from 2 AM to 4 AM
     * $verifier = RedirectMiddleware::timeWindow(2, 4);
     * $middleware = new RedirectMiddleware('/maintenance', $responseFactory, $verifier);
     */
    public static function timeWindow(int $startHour, int $endHour, string $timezone = 'UTC'): \Closure
    {
        return static function(ServerRequestInterface $request) use ($startHour, $endHour, $timezone): bool {
            $currentHour = (int) (new \DateTime('now', new \DateTimeZone($timezone)))->format('H');
            
            if ($startHour <= $endHour) {
                return $currentHour >= $startHour && $currentHour < $endHour;
            } else {
                // Overnight window (e.g., 22:00 to 06:00)
                return $currentHour >= $startHour || $currentHour < $endHour;
            }
        };
    }

    /**
     * Path-based verifier - redirects requests matching specific path patterns.
     *
     * @param array<string> $patterns Path patterns to match (supports startsWith logic)
     * @param bool $exactMatch Whether to use exact matching instead of startsWith
     * @return \Closure Verifier function that checks request path
     *
     * @example
     * // Redirect old API paths
     * $verifier = RedirectMiddleware::pathMatches(['/old/', '/deprecated/', '/v1/']);
     * $middleware = new RedirectMiddleware('/api/v2/', $responseFactory, $verifier, true);
     */
    public static function pathMatches(array $patterns, bool $exactMatch = false): \Closure
    {
        return static function(ServerRequestInterface $request) use ($patterns, $exactMatch): bool {
            $path = $request->getUri()->getPath();
            
            foreach ($patterns as $pattern) {
                if ($exactMatch ? ($path === $pattern) : str_starts_with($path, $pattern)) {
                    return true;
                }
            }
            return false;
        };
    }

    /**
     * Authentication-based verifier - redirects unauthenticated users.
     *
     * @param string $userAttribute Request attribute key for user object
     * @return \Closure Verifier function that checks authentication status
     *
     * @example
     * $verifier = RedirectMiddleware::requireAuth('user');
     * $middleware = new RedirectMiddleware('/login', $responseFactory, $verifier);
     */
    public static function requireAuth(string $userAttribute = 'user'): \Closure
    {
        return static fn(ServerRequestInterface $request): bool => 
            $request->getAttribute($userAttribute) === null;
    }

    /**
     * Feature flag verifier - redirects based on feature flag status.
     *
     * @param string $flagName Feature flag name
     * @param string $flagsAttribute Request attribute key for feature flags
     * @param bool $redirectWhenEnabled Whether to redirect when flag is enabled (true) or disabled (false)
     * @return \Closure Verifier function that checks feature flag status
     *
     * @example
     * // Redirect to new site when feature flag is enabled
     * $verifier = RedirectMiddleware::featureFlag('new_site', 'feature_flags', true);
     * $middleware = new RedirectMiddleware('/new-site', $responseFactory, $verifier);
     */
    public static function featureFlag(
        string $flagName, 
        string $flagsAttribute = 'feature_flags', 
        bool $redirectWhenEnabled = true
    ): \Closure {
        return static function(ServerRequestInterface $request) use ($flagName, $flagsAttribute, $redirectWhenEnabled): bool {
            $flags = $request->getAttribute($flagsAttribute, []);
            $isEnabled = $flags[$flagName] ?? false;
            return $redirectWhenEnabled ? $isEnabled : !$isEnabled;
        };
    }

    /**
     * IP-based verifier - redirects requests from specific IP addresses or ranges.
     *
     * @param array<string> $ipList List of IPs or CIDR ranges to match
     * @param string $ipAttribute Request attribute key for client IP
     * @return \Closure Verifier function that checks client IP
     *
     * @example
     * // Block specific IPs
     * $verifier = RedirectMiddleware::ipMatches(['192.168.1.100', '10.0.0.0/8']);
     * $middleware = new RedirectMiddleware('/blocked', $responseFactory, $verifier);
     */
    public static function ipMatches(array $ipList, string $ipAttribute = 'client_ip'): \Closure
    {
        return static function(ServerRequestInterface $request) use ($ipList, $ipAttribute): bool {
            $clientIp = $request->getAttribute($ipAttribute) 
                ?? $request->getServerParams()['REMOTE_ADDR'] 
                ?? '';

            foreach ($ipList as $ip) {
                if (str_contains($ip, '/')) {
                    // CIDR range check
                    if (self::ipInRange($clientIp, $ip)) {
                        return true;
                    }
                } elseif ($clientIp === $ip) {
                    return true;
                }
            }
            return false;
        };
    }

    /**
     * HTTP method verifier - redirects specific HTTP methods.
     *
     * @param array<string> $methods HTTP methods to redirect
     * @return \Closure Verifier function that checks request method
     *
     * @example
     * // Redirect POST/PUT/DELETE to GET endpoint
     * $verifier = RedirectMiddleware::httpMethods(['POST', 'PUT', 'DELETE']);
     * $middleware = new RedirectMiddleware('/readonly', $responseFactory, $verifier);
     */
    public static function httpMethods(array $methods): \Closure
    {
        return static fn(ServerRequestInterface $request): bool => 
            in_array($request->getMethod(), $methods, true);
    }

    /**
     * Query parameter verifier - redirects based on query parameter presence/value.
     *
     * @param string $paramName Query parameter name
     * @param string|null $expectedValue Expected parameter value (null to check presence only)
     * @return \Closure Verifier function that checks query parameters
     *
     * @example
     * // Redirect if 'mobile=1' query parameter is present
     * $verifier = RedirectMiddleware::queryParam('mobile', '1');
     * $middleware = new RedirectMiddleware('https://m.example.com', $responseFactory, $verifier);
     */
    public static function queryParam(string $paramName, ?string $expectedValue = null): \Closure
    {
        return static function(ServerRequestInterface $request) use ($paramName, $expectedValue): bool {
            $queryParams = $request->getQueryParams();
            
            if (!isset($queryParams[$paramName])) {
                return false;
            }
            
            if ($expectedValue === null) {
                return true; // Just check presence
            }
            
            return $queryParams[$paramName] === $expectedValue;
        };
    }

    /**
     * Header-based verifier - redirects based on request header presence/value.
     *
     * @param string $headerName Header name to check
     * @param string|null $expectedValue Expected header value (null to check presence only)
     * @param bool $caseInsensitive Whether to perform case-insensitive comparison
     * @return \Closure Verifier function that checks request headers
     *
     * @example
     * // Redirect API requests without proper version header
     * $verifier = RedirectMiddleware::header('X-API-Version', 'v2');
     * $middleware = new RedirectMiddleware('/api/v1/', $responseFactory, $verifier);
     */
    public static function header(string $headerName, ?string $expectedValue = null, bool $caseInsensitive = true): \Closure
    {
        return static function(ServerRequestInterface $request) use ($headerName, $expectedValue, $caseInsensitive): bool {
            $headerValue = $request->getHeaderLine($headerName);
            
            if ($headerValue === '') {
                return $expectedValue === null ? false : true; // No header found
            }
            
            if ($expectedValue === null) {
                return true; // Just check presence
            }
            
            return $caseInsensitive 
                ? strcasecmp($headerValue, $expectedValue) === 0
                : $headerValue === $expectedValue;
        };
    }

    /**
     * Rate limit verifier - redirects when rate limit is exceeded.
     *
     * @param string $rateLimitAttribute Request attribute key for rate limit status
     * @return \Closure Verifier function that checks rate limit status
     *
     * @example
     * $verifier = RedirectMiddleware::rateLimitExceeded('rate_limit_exceeded');
     * $middleware = new RedirectMiddleware('/rate-limited', $responseFactory, $verifier);
     */
    public static function rateLimitExceeded(string $rateLimitAttribute = 'rate_limit_exceeded'): \Closure
    {
        return static fn(ServerRequestInterface $request): bool => 
            $request->getAttribute($rateLimitAttribute, false) === true;
    }

    /**
     * Combined verifier - combines multiple verifiers with AND/OR logic.
     *
     * @param array<callable> $verifiers List of verifier functions
     * @param bool $useOrLogic Whether to use OR logic (true) or AND logic (false)
     * @return \Closure Combined verifier function
     *
     * @example
     * // Redirect if it's maintenance time AND user is not admin
     * $verifier = RedirectMiddleware::combine([
     *     RedirectMiddleware::timeWindow(2, 4),
     *     fn($req) => !$req->getAttribute('user')?->isAdmin()
     * ], false); // AND logic
     */
    public static function combine(array $verifiers, bool $useOrLogic = false): \Closure
    {
        return static function(ServerRequestInterface $request) use ($verifiers, $useOrLogic): bool {
            foreach ($verifiers as $verifier) {
                $result = $verifier($request);
                
                if ($useOrLogic && $result) {
                    return true; // OR: return true on first success
                } elseif (!$useOrLogic && !$result) {
                    return false; // AND: return false on first failure
                }
            }
            
            return !$useOrLogic; // OR: false if none succeeded, AND: true if all succeeded
        };
    }

    /**
     * Helper method to check if IP is in CIDR range.
     *
     * @param string $ip IP address to check
     * @param string $cidr CIDR range (e.g., '192.168.1.0/24')
     * @return bool Whether IP is in range
     */
    private static function ipInRange(string $ip, string $cidr): bool
    {
        [$range, $netmask] = explode('/', $cidr, 2);
        $rangeDecimal = ip2long($range);
        $ipDecimal = ip2long($ip);
        $wildcardDecimal = pow(2, (32 - $netmask)) - 1;
        $netmaskDecimal = ~ $wildcardDecimal;
        
        return ($ipDecimal & $netmaskDecimal) === ($rangeDecimal & $netmaskDecimal);
    }
}
