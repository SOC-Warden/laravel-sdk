<?php

namespace SOCWarden\Listeners;

use Illuminate\Auth\Events\Failed;
use Illuminate\Auth\Events\Login;
use Illuminate\Auth\Events\Logout;
use Illuminate\Auth\Events\PasswordReset;
use Illuminate\Auth\Events\Registered;
use Illuminate\Events\Dispatcher;
use SOCWarden\SOCWardenClient;

class AuthEventSubscriber
{
    public function __construct(private SOCWardenClient $client) {}

    public function handleLogin(Login $event): void
    {
        $this->client->track('auth.login.success', actor: $event->user);
    }

    public function handleFailed(Failed $event): void
    {
        // Only the email is extracted from credentials — the password is intentionally
        // excluded to prevent plaintext credentials from being forwarded to the ingestor.
        $this->client->track('auth.login.failure', actorEmail: $event->credentials['email'] ?? null);
    }

    public function handleLogout(Logout $event): void
    {
        if ($event->user) {
            $this->client->track('auth.logout', actor: $event->user);
        }
    }

    public function handleRegistered(Registered $event): void
    {
        $this->client->track('account.created', actor: $event->user);
    }

    public function handlePasswordReset(PasswordReset $event): void
    {
        $this->client->track('auth.password.changed', actor: $event->user);
    }

    public function subscribe(Dispatcher $events): void
    {
        $events->listen(Login::class, [self::class, 'handleLogin']);
        $events->listen(Failed::class, [self::class, 'handleFailed']);
        $events->listen(Logout::class, [self::class, 'handleLogout']);
        $events->listen(Registered::class, [self::class, 'handleRegistered']);
        $events->listen(PasswordReset::class, [self::class, 'handlePasswordReset']);
    }
}
