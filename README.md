# SOCWarden Laravel SDK

Security observability SDK for Laravel applications. Sends security events to the SOCWarden ingestor.

## Installation

```bash
composer require soc-warden/laravel-sdk
```

## Configuration

Publish the config file:

```bash
php artisan vendor:publish --tag=socwarden-config
```

Add to your `.env`:

```
SOCWARDEN_API_KEY=sk_live_your_key_here
```

## Usage

### Track events manually

```php
use SOCWarden\Facades\SOCWarden;

SOCWarden::track('auth.login.success', [
    'actor_id' => $user->id,
    'actor_email' => $user->email,
]);
```

### Middleware

Register the middleware to automatically capture request context:

```php
// bootstrap/app.php (Laravel 11+)
->withMiddleware(function (Middleware $middleware) {
    $middleware->append(\SOCWarden\Middleware\CaptureContext::class);
})
```

### Automatic Auth Events

By default, the SDK listens to Laravel auth events (`Login`, `Failed`, `Logout`, `Registered`, `PasswordReset`) and tracks them automatically. Disable with:

```
SOCWARDEN_LISTEN_AUTH=false
```

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `SOCWARDEN_API_KEY` | — | Your SOCWarden API key |
| `SOCWARDEN_ENDPOINT` | `https://ingestor.socwarden.com` | Ingestor endpoint |
| `SOCWARDEN_AUTO_CONTEXT` | `true` | Auto-collect request context |
| `SOCWARDEN_QUEUE` | `true` | Dispatch events via queue |
| `SOCWARDEN_QUEUE_CONNECTION` | `null` | Queue connection name |
| `SOCWARDEN_QUEUE_NAME` | `default` | Queue name |
| `SOCWARDEN_BROWSER_HEADER` | `X-SOCWarden-Context` | Browser context relay header |
| `SOCWARDEN_LISTEN_AUTH` | `true` | Auto-track auth events |
| `SOCWARDEN_TIMEOUT` | `5` | HTTP timeout in seconds |
