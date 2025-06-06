# RedirectMiddleware

English | [Русский](README.ru.md)

HTTP middleware package for PSR-15 middleware stack with flexible conditional logic, pre-built verifiers for common scenarios, and specialized HTTPS enforcement.

## Features

- ✅ Conditional redirects with custom verifier functions
- ✅ Dynamic verifier extraction from request attributes
- ✅ Support for permanent (301) and temporary (302) redirects
- ✅ Separate verifier factory class for reusability
- ✅ Static factory methods for popular scenarios
- ✅ Lazy instantiation through DI containers
- ✅ Combined verifiers support with AND/OR logic
- ✅ Specialized HTTPS enforcement middleware
- ✅ Asymmetric property visibility (private(set)) for PHP 8.4

## Requirements

- PHP 8.4+
- PSR-7 HTTP Message Interface
- PSR-15 HTTP Server Request Handlers
- PSR-11 Container Interface (for lazy instantiation)

## Installation

```bash
composer require bermuda/http-middleware-redirect
```

## RedirectMiddleware

Flexible conditional redirect middleware with custom verifier functions.

### Quick Start

```php
use Bermuda\Http\Middleware\RedirectMiddleware;
use Psr\Http\Message\ResponseFactoryInterface;

// Always redirect to specified URL
$middleware = new RedirectMiddleware(
    location: '/maintenance',
    responseFactory: $responseFactory
);

// Conditional redirect with custom verifier
$middleware = new RedirectMiddleware(
    location: '/login',
    responseFactory: $responseFactory,
    verifier: fn($request) => $request->getAttribute('user') === null,
    isPermanent: false
);
```

### Using Static Factory Methods

```php
// Maintenance mode
$middleware = RedirectMiddleware::forMaintenanceMode(
    '/maintenance',
    '/app/maintenance.flag',
    $responseFactory
);

// HTTPS enforcement
$middleware = RedirectMiddleware::forHttpsEnforcement(
    'https://secure.example.com',
    $responseFactory
);

// Mobile device detection
$middleware = RedirectMiddleware::forMobileDevices(
    'https://m.example.com',
    $responseFactory
);
```

### Verifier Signature

All verifier functions must follow the same signature:

```php
(ServerRequestInterface $request): bool
```

The verifier receives a PSR-7 ServerRequestInterface and returns a boolean indicating whether the request should be redirected (true) or allowed to continue (false).

### RedirectVerifiers Class

Separate factory class for creating verifiers:

```php
use Bermuda\Http\Middleware\RedirectVerifiers;

// Various types of verifiers
$maintenanceVerifier = RedirectVerifiers::maintenanceMode('/app/maintenance.flag');
$httpsVerifier = RedirectVerifiers::httpsEnforcement();
$mobileVerifier = RedirectVerifiers::mobileDevice();
$timeVerifier = RedirectVerifiers::timeWindow(2, 4, 'UTC');
$pathVerifier = RedirectVerifiers::pathMatcher(['/old/', '/deprecated/']);
$authVerifier = RedirectVerifiers::authenticationRequired('user');
$featureFlagVerifier = RedirectVerifiers::featureFlag('new_site');
$ipVerifier = RedirectVerifiers::ipMatcher(['192.168.1.100', '10.0.0.0/8']);
$methodVerifier = RedirectVerifiers::httpMethod(['POST', 'PUT', 'DELETE']);
$queryVerifier = RedirectVerifiers::queryParameter('mobile', '1');
$headerVerifier = RedirectVerifiers::header('X-API-Version', 'v2');
$rateLimitVerifier = RedirectVerifiers::rateLimit('rate_limit_exceeded');
```

### Available Static Factory Methods

#### Maintenance Mode

```php
$middleware = RedirectMiddleware::forMaintenanceMode(
    location: '/maintenance',
    maintenanceFlagFile: '/app/maintenance.flag',
    responseFactory: $responseFactory,
    isPermanent: false
);
```

#### HTTPS Enforcement

```php
$middleware = RedirectMiddleware::forHttpsEnforcement(
    httpsLocation: 'https://secure.example.com',
    responseFactory: $responseFactory
);
```

#### Mobile Devices

```php
$middleware = RedirectMiddleware::forMobileDevices(
    mobileLocation: 'https://m.example.com',
    responseFactory: $responseFactory,
    mobileKeywords: ['Mobile', 'iPhone', 'Android'],
    isPermanent: false
);
```

#### Time Window

```php
$middleware = RedirectMiddleware::forTimeWindow(
    location: '/maintenance',
    startHour: 2,
    endHour: 4,
    responseFactory: $responseFactory,
    timezone: 'America/New_York'
);
```

#### Path Patterns

```php
$middleware = RedirectMiddleware::forPathPatterns(
    location: '/api/v2',
    pathPatterns: ['/api/v1/', '/deprecated/'],
    responseFactory: $responseFactory,
    exactMatch: false,
    isPermanent: true
);
```

#### Authentication Required

```php
$middleware = RedirectMiddleware::forAuthenticationRequired(
    loginLocation: '/login',
    responseFactory: $responseFactory,
    userAttribute: 'user'
);
```

#### Feature Flag

```php
$middleware = RedirectMiddleware::forFeatureFlag(
    location: '/new-site',
    flagName: 'new_site_enabled',
    responseFactory: $responseFactory,
    flagsAttribute: 'feature_flags',
    redirectWhenEnabled: true
);
```

#### IP Addresses

```php
$middleware = RedirectMiddleware::forIpAddresses(
    location: '/blocked',
    ipList: ['192.168.1.100', '10.0.0.0/8'],
    responseFactory: $responseFactory
);
```

#### HTTP Methods

```php
$middleware = RedirectMiddleware::forHttpMethods(
    location: '/readonly',
    httpMethods: ['POST', 'PUT', 'DELETE'],
    responseFactory: $responseFactory
);
```

#### Combined Conditions

```php
$middleware = RedirectMiddleware::forCombinedConditions(
    location: '/restricted',
    verifiers: [
        RedirectVerifiers::timeWindow(2, 4),
        RedirectVerifiers::authenticationRequired()
    ],
    responseFactory: $responseFactory,
    useOrLogic: false // AND logic
);
```

### Combined Verifiers

```php
// AND logic - all conditions must be true
$verifier = RedirectVerifiers::combined([
    RedirectVerifiers::timeWindow(2, 4),
    RedirectVerifiers::authenticationRequired()
], useOrLogic: false);

// OR logic - any condition must be true
$verifier = RedirectVerifiers::combined([
    RedirectVerifiers::maintenanceMode('/app/maintenance.flag'),
    RedirectVerifiers::featureFlag('emergency_redirect')
], useOrLogic: true);
```

### Dynamic Verifiers

You can set verifiers dynamically through request attributes:

```php
// In previous middleware
$verifier = fn($request) => $request->getAttribute('user')?->isBlocked();
$request = RedirectMiddleware::attachDynamicVerifier($request, $verifier);

// Later RedirectMiddleware will use this verifier
$middleware = new RedirectMiddleware('/blocked', $responseFactory);
```

### DI Container Integration

```php
use Psr\Container\ContainerInterface;

// Register in DI container using lazy factories
$container->set('maintenance.redirect', RedirectMiddleware::createLazyFactory(
    '/maintenance',
    RedirectVerifiers::maintenanceMode('/app/maintenance.flag'),
    false
));

// Usage
$middleware = $container->get('maintenance.redirect');
```

### Immutable Methods

The class supports immutable methods for configuration:

```php
$middleware = new RedirectMiddleware('/old', $responseFactory);

$newMiddleware = $middleware
    ->withLocation('/new')
    ->withPermanentRedirect(true)
    ->withVerifier(RedirectVerifiers::httpsEnforcement());
```

### Asymmetric Property Visibility

PHP 8.4 asymmetric property visibility `private(set)` is used:

```php
$middleware = new RedirectMiddleware('/test', $responseFactory);

// Properties are readable
echo $middleware->location;        // '/test'
echo $middleware->isPermanent;     // false

// But cannot be modified directly (only through constructor or with* methods)
// $middleware->location = '/new'; // Compile error
```

## HttpsEnforcementMiddleware

A specialized middleware for enforcing HTTPS connections by automatically redirecting all HTTP requests to their HTTPS equivalents. This middleware provides a focused solution for ensuring secure connections across your entire application.

### Features

- ✅ Automatic HTTP to HTTPS conversion
- ✅ Preserves original path, query parameters, and fragment
- ✅ Uses permanent (301) redirects for SEO benefits
- ✅ Configurable HTTPS port (default: 443)
- ✅ Optional port preservation for development environments
- ✅ Bypasses redirect if request is already HTTPS
- ✅ Asymmetric property visibility (private(set)) for PHP 8.4

### Basic Usage

```php
use Bermuda\Http\Middleware\HttpsEnforcementMiddleware;

// Simple HTTPS enforcement
$httpsMiddleware = HttpsEnforcementMiddleware::create($responseFactory);

// With custom HTTPS port
$httpsMiddleware = HttpsEnforcementMiddleware::withCustomPort($responseFactory, 8443);

// With port preservation (for development)
$httpsMiddleware = HttpsEnforcementMiddleware::withPortPreservation($responseFactory);
```

### Configuration Options

```php
// Basic configuration
$middleware = new HttpsEnforcementMiddleware($responseFactory);

// Custom HTTPS port
$middleware = new HttpsEnforcementMiddleware(
    responseFactory: $responseFactory,
    httpsPort: 8443
);

// Preserve original port numbers
$middleware = new HttpsEnforcementMiddleware(
    responseFactory: $responseFactory,
    httpsPort: 443,
    preservePort: true
);
```

### Immutable Configuration

```php
$middleware = new HttpsEnforcementMiddleware($responseFactory);

$customMiddleware = $middleware
    ->withHttpsPort(8443)
    ->withPreservePort(true);
```

### DI Container Integration

```php
// Register in DI container
$container->set('https.enforcement', HttpsEnforcementMiddleware::createLazyFactory());

// With custom configuration
$container->set('https.enforcement', HttpsEnforcementMiddleware::createLazyFactory(8443, true));
```

### URL Conversion Examples

| Original HTTP URL | HTTPS Result | Configuration |
|-------------------|-------------|---------------|
| `http://example.com/path` | `https://example.com/path` | Default |
| `http://example.com:8080/path` | `https://example.com:8443/path` | Custom port (8443) |
| `http://example.com:8080/path` | `https://example.com:8080/path` | Port preservation |
| `http://example.com/path?q=1#frag` | `https://example.com/path?q=1#frag` | Preserves query & fragment |

### Properties

The middleware exposes read-only properties using PHP 8.4's asymmetric visibility:

```php
$middleware = new HttpsEnforcementMiddleware($responseFactory, 8443, true);

echo $middleware->httpsPort;     // 8443
echo $middleware->preservePort;  // true

// Properties cannot be modified directly
// $middleware->httpsPort = 443; // Compile error
```

### Security Benefits

- **Encryption**: Ensures all traffic uses encrypted connections
- **SEO**: HTTPS is a ranking factor for search engines
- **Browser Security**: Prevents mixed content warnings
- **Attack Prevention**: Protects against man-in-the-middle attacks
- **Compliance**: Helps meet security compliance requirements

### Use Cases

- **Production Applications**: Enforce HTTPS across entire application
- **API Security**: Ensure all API endpoints use secure connections
- **Development**: Test HTTPS behavior in local environments
- **Load Balancer Integration**: Handle HTTPS enforcement at application level
- **Security Compliance**: Meet requirements for encrypted communications

## How It Works

### Verifier Priority (RedirectMiddleware)

1. **Static verifier** (provided in constructor) - highest priority
2. **Dynamic verifier** (from request attributes) - fallback
3. **No verifier** = always redirect (default behavior)

### Processing Logic

```php
if ($verifier === null) {
    return redirect(); // Always redirect
}

if ($verifier($request) === true) {
    return redirect(); // Condition met - redirect
}

return $handler->handle($request); // Continue to next middleware
```

## Real-world Usage Examples

### Maintenance Mode with Admin Exceptions

```php
$maintenanceMiddleware = RedirectMiddleware::forCombinedConditions(
    '/maintenance',
    [
        RedirectVerifiers::maintenanceMode('/app/maintenance.flag'),
        fn($req) => !$req->getAttribute('user')?->isAdmin()
    ],
    $responseFactory,
    useOrLogic: false // AND logic
);
```

### Mobile User Redirection with Time Constraints

```php
$mobileRedirectMiddleware = RedirectMiddleware::forCombinedConditions(
    'https://m.example.com',
    [
        RedirectVerifiers::mobileDevice(),
        RedirectVerifiers::timeWindow(0, 23) // All day
    ],
    $responseFactory,
    useOrLogic: false
);
```

### Legacy API Redirection with Path Preservation

```php
$apiRedirectMiddleware = RedirectMiddleware::forPathPatterns(
    '/api/v2',
    ['/api/v1/'],
    $responseFactory,
    isPermanent: true
);
```

### HTTPS Enforcement in Production

```php
$httpsMiddleware = HttpsEnforcementMiddleware::create($responseFactory);
```

## Custom Verifiers

```php
// Complex business logic
$customVerifier = function (ServerRequestInterface $request): bool {
    $user = $request->getAttribute('user');
    if (!$user) {
        return false;
    }

    $subscription = $user->getSubscription();
    $requestedFeature = $request->getAttribute('requested_feature');
    
    return $subscription->isPlanExceeded($requestedFeature);
};

$middleware = new RedirectMiddleware(
    '/upgrade-required',
    $responseFactory,
    $customVerifier
);
```

## Available Verifiers

### Maintenance Mode

```php
RedirectVerifiers::maintenanceMode(string $maintenanceFlagFile): Closure
```

Redirects when maintenance flag file exists.

### HTTPS Enforcement

```php
RedirectVerifiers::httpsEnforcement(): Closure
```

Redirects HTTP requests to HTTPS.

### Mobile Device Detection

```php
RedirectVerifiers::mobileDevice(array $mobileKeywords = ['Mobile', 'Android', 'iPhone', 'iPad']): Closure
```

Redirects mobile device requests based on User-Agent header.

### Time Window

```php
RedirectVerifiers::timeWindow(int $startHour, int $endHour, string $timezone = 'UTC'): Closure
```

Redirects requests during specified time window.

### Path Matching

```php
RedirectVerifiers::pathMatcher(array $pathPatterns, bool $exactMatch = false): Closure
```

Redirects requests matching specific path patterns.

### Authentication Required

```php
RedirectVerifiers::authenticationRequired(string $userAttribute = 'user'): Closure
```

Redirects unauthenticated users.

### Feature Flag

```php
RedirectVerifiers::featureFlag(
    string $flagName,
    string $flagsAttribute = 'feature_flags',
    bool $redirectWhenEnabled = true
): Closure
```

Redirects based on feature flag status.

### IP Matching

```php
RedirectVerifiers::ipMatcher(array $ipList, string $ipAttribute = 'client_ip'): Closure
```

Redirects requests from specific IP addresses or CIDR ranges.

### HTTP Methods

```php
RedirectVerifiers::httpMethod(array $httpMethods): Closure
```

Redirects specific HTTP methods.

### Query Parameters

```php
RedirectVerifiers::queryParameter(string $paramName, ?string $expectedValue = null): Closure
```

Redirects based on query parameter presence/value.

### Headers

```php
RedirectVerifiers::header(
    string $headerName,
    ?string $expectedValue = null,
    bool $caseInsensitive = true
): Closure
```

Redirects based on request headers.

### Rate Limiting

```php
RedirectVerifiers::rateLimit(string $rateLimitAttribute = 'rate_limit_exceeded'): Closure
```

Redirects when rate limit is exceeded.

### Combined Verifiers

```php
RedirectVerifiers::combined(array $verifiers, bool $useOrLogic = false): Closure
```

Combines multiple verifiers with AND/OR logic.

## Advanced Examples

### Multi-condition E-commerce Scenario

```php
$ecommerceRedirect = new RedirectMiddleware(
    '/checkout-unavailable',
    $responseFactory,
    RedirectVerifiers::combined([
        // During business hours only
        RedirectVerifiers::timeWindow(9, 17, 'America/New_York'),
        // AND user has items in cart
        fn($req) => !empty($req->getAttribute('cart_items', [])),
        // AND payment gateway is down
        fn($req) => $req->getAttribute('payment_gateway_down', false)
    ], useOrLogic: false)
);
```

### Geographic Redirection

```php
$geoRedirect = new RedirectMiddleware(
    'https://eu.example.com',
    $responseFactory,
    function (ServerRequestInterface $request): bool {
        $countryCode = $request->getAttribute('geoip_country');
        $euCountries = ['DE', 'FR', 'IT', 'ES', 'NL', 'BE'];
        
        return in_array($countryCode, $euCountries, true);
    }
);
```

### A/B Testing Redirect

```php
$abTestRedirect = new RedirectMiddleware(
    '/variation-b',
    $responseFactory,
    function (ServerRequestInterface $request): bool {
        $userId = $request->getAttribute('user_id');
        if (!$userId) {
            return false;
        }

        // Simple hash-based A/B testing
        return (crc32((string) $userId) % 100) < 50; // 50% of users
    }
);
```
## License

MIT License. See [LICENSE](LICENSE) for details.
