<?php

return [
    // SOCWarden API key (sk_live_...)
    'api_key' => env('SOCWARDEN_API_KEY'),

    // Ingestor endpoint
    'endpoint' => env('SOCWARDEN_ENDPOINT', 'https://ingest.socwarden.io'),

    // Automatically collect request context (method, path, referer, server info)
    'auto_context' => env('SOCWARDEN_AUTO_CONTEXT', true),

    // Dispatch events via Laravel queue (recommended for production)
    'queue' => env('SOCWARDEN_QUEUE', true),

    // Queue connection and name
    'queue_connection' => env('SOCWARDEN_QUEUE_CONNECTION', null), // null = default
    'queue_name' => env('SOCWARDEN_QUEUE_NAME', 'default'),

    // Browser context header name (for relay mode)
    'browser_context_header' => env('SOCWARDEN_BROWSER_HEADER', 'X-SOCWarden-Context'),

    // Auto-listen to Laravel auth events
    'listen_auth_events' => env('SOCWARDEN_LISTEN_AUTH', true),

    // HTTP timeout (seconds)
    'timeout' => env('SOCWARDEN_TIMEOUT', 5),
];
