<?php

namespace SOCWarden;

use Illuminate\Support\ServiceProvider;

class SOCWardenServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__ . '/../config/socwarden.php', 'socwarden-sdk');

        $this->app->singleton(SOCWardenClient::class, function ($app) {
            return new SOCWardenClient(
                apiKey: config('socwarden-sdk.api_key', ''),
                endpoint: config('socwarden-sdk.endpoint', 'https://ingestor.socwarden.com'),
                timeout: config('socwarden-sdk.timeout', 5),
                autoContext: config('socwarden-sdk.auto_context', true),
                useQueue: config('socwarden-sdk.queue', true),
                queueConnection: config('socwarden-sdk.queue_connection'),
                queueName: config('socwarden-sdk.queue_name', 'default'),
                browserContextHeader: config('socwarden-sdk.browser_context_header', 'X-SOCWarden-Context'),
            );
        });
    }

    public function boot(): void
    {
        $this->publishes([
            __DIR__ . '/../config/socwarden.php' => config_path('socwarden-sdk.php'),
        ], 'socwarden-config');

        // Register auth event subscriber
        if (config('socwarden-sdk.listen_auth_events', true)) {
            $this->app['events']->subscribe(Listeners\AuthEventSubscriber::class);
        }
    }
}
