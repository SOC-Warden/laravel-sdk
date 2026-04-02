<?php

namespace SOCWarden;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;

class SOCWardenClient
{
    private const BACKOFF_CACHE_KEY = 'socwarden:quota_backoff_until';

    private const BACKOFF_DURATION = 3600; // 1 hour

    private const PROBE_INTERVAL = 300; // 5 min probe retry

    private ?Request $request = null;

    public function __construct(
        private string $apiKey,
        private string $endpoint,
        private int $timeout,
        private bool $autoContext,
        private bool $useQueue,
        private ?string $queueConnection,
        private string $queueName,
        private string $browserContextHeader,
    ) {}

    /**
     * Start building an event with the fluent API.
     *
     *   SOCWarden::event('data.exported')
     *       ->actor($user)
     *       ->resource($report)
     *       ->meta('format', 'csv')
     *       ->send();
     */
    public function event(string $event): EventBuilder
    {
        return new EventBuilder($event);
    }

    /**
     * Track a security event using named arguments.
     *
     *   SOCWarden::track('auth.login.success', actor: $user);
     *   SOCWarden::track('auth.login.failure', actorEmail: $request->email);
     *   SOCWarden::track('data.exported', actor: $user, metadata: ['format' => 'csv'], resource: $report);
     */
    public function track(
        string $event,
        Model|string|null $actor = null,
        ?string $actorId = null,
        ?string $actorEmail = null,
        ?string $ip = null,
        ?string $userAgent = null,
        ?array $metadata = null,
        \DateTimeInterface|string|null $timestamp = null,
        Model|string|null $resource = null,
        string|int|null $resourceId = null,
    ): void {
        $data = $this->resolveNamedArgs($actor, $actorId, $actorEmail, $ip, $userAgent, $metadata, $timestamp, $resource, $resourceId);
        $this->dispatch($event, $data);
    }

    /**
     * Track a security event using a raw data array.
     *
     *   SOCWarden::trackData('auth.login.success', [
     *       'actor_id'    => $user->id,
     *       'actor_email' => $user->email,
     *       'metadata'    => ['role' => 'admin'],
     *   ]);
     */
    public function trackData(string $event, array $data = []): void
    {
        $this->dispatch($event, $data);
    }

    /**
     * Set the current request for context extraction.
     * Called by the CaptureContext middleware.
     */
    public function setRequest(Request $request): void
    {
        $this->request = $request;
    }

    // -------------------------------------------------------------------------
    //  Internal
    // -------------------------------------------------------------------------

    private function resolveNamedArgs(
        Model|string|null $actor,
        ?string $actorId,
        ?string $actorEmail,
        ?string $ip,
        ?string $userAgent,
        ?array $metadata,
        \DateTimeInterface|string|null $timestamp,
        Model|string|null $resource,
        string|int|null $resourceId,
    ): array {
        $data = [];

        // Actor: model auto-reads id + email; string is just id
        if ($actor instanceof Model) {
            $data['actor_id'] = (string) $actor->getKey();
            $data['actor_email'] = $actor->email ?? null;
        } elseif (is_string($actor)) {
            $data['actor_id'] = $actor;
        }

        // Explicit scalars override model-resolved values
        if ($actorId !== null) {
            $data['actor_id'] = $actorId;
        }
        if ($actorEmail !== null) {
            $data['actor_email'] = $actorEmail;
        }
        if ($ip !== null) {
            $sanitized = $this->sanitizeIP($ip);
            if ($sanitized !== null) {
                $data['ip'] = $sanitized;
            }
        }
        if ($userAgent !== null) {
            $data['user_agent'] = $userAgent;
        }
        if ($metadata !== null) {
            $data['metadata'] = $metadata;
        }
        if ($timestamp !== null) {
            $data['timestamp'] = $timestamp instanceof \DateTimeInterface
                ? $timestamp->format('c')
                : $timestamp;
        }

        // Resource: model auto-reads class name + key
        if ($resource instanceof Model) {
            $data['metadata'] ??= [];
            $data['metadata']['resource_type'] = class_basename($resource);
            $data['metadata']['resource_id'] = (string) $resource->getKey();
        } elseif (is_string($resource)) {
            $data['metadata'] ??= [];
            $data['metadata']['resource_type'] = $resource;
            if ($resourceId !== null) {
                $data['metadata']['resource_id'] = (string) $resourceId;
            }
        }

        return array_filter($data, fn ($v) => $v !== null);
    }

    private function dispatch(string $event, array $data): void
    {
        $payload = $this->buildPayload($event, $data);

        if ($this->useQueue) {
            dispatch(function () use ($payload) {
                $this->send($payload);
            })->onConnection($this->queueConnection)
              ->onQueue($this->queueName);
        } else {
            try {
                $this->send($payload);
            } catch (\Throwable $e) {
                Log::warning('[SOCWarden] Failed to send event: ' . $e->getMessage());
            }
        }
    }

    private function buildPayload(string $event, array $data): array
    {
        $payload = [
            'event' => $event,
            'source' => 'sdk',
        ];

        foreach (['actor_id', 'actor_email', 'ip', 'user_agent', 'metadata', 'timestamp'] as $field) {
            if (isset($data[$field])) {
                $payload[$field] = $data[$field];
            }
        }

        if ($this->autoContext) {
            $payload['context'] = $this->collectContext($data);
        }

        return $payload;
    }

    private function collectContext(array $data): array
    {
        $context = [
            'sdk' => [
                'name' => 'socwarden-laravel',
                'version' => '1.0.0',
            ],
            'server' => [
                'hostname' => gethostname(),
                'runtime' => 'PHP ' . PHP_VERSION,
                'pid' => getmypid(),
            ],
        ];

        $request = $this->request ?? request();

        if ($request) {
            $context['request'] = [
                'method' => $request->method(),
                'path' => $request->path(),
                'query_string' => $this->sanitizeQueryString($request->getQueryString() ?? ''),
                'referer' => $request->header('Referer'),
                'origin' => $request->header('Origin'),
                'content_type' => $request->header('Content-Type'),
                'accept_language' => $request->header('Accept-Language'),
                'request_id' => $request->header('X-Request-ID') ?? $request->header('X-Correlation-ID'),
            ];

            $browserContext = $request->header($this->browserContextHeader);
            if ($browserContext) {
                $base64Decoded = base64_decode($browserContext, true);
                $decoded = $base64Decoded ? json_decode($base64Decoded, true) : json_decode($browserContext, true);
                if (is_array($decoded)) {
                    $context = array_merge($context, $decoded);
                }
            }
        }

        return $context;
    }

    private function sanitizeIP(?string $ip): ?string
    {
        if ($ip === null) {
            return null;
        }
        return filter_var($ip, FILTER_VALIDATE_IP) !== false ? $ip : null;
    }

    private function sanitizeQueryString(string $qs): string
    {
        if ($qs === '') {
            return '';
        }

        $sensitive = ['token', 'key', 'password', 'secret', 'code', 'auth', 'session', 'csrf'];
        $parts = [];
        foreach (explode('&', $qs) as $pair) {
            $kv = explode('=', $pair, 2);
            $paramName = strtolower($kv[0]);
            foreach ($sensitive as $s) {
                if (str_contains($paramName, $s)) {
                    $kv[1] = '[REDACTED]';

                    break;
                }
            }
            $parts[] = implode('=', $kv);
        }

        return implode('&', $parts);
    }

    private function send(array $payload): array
    {
        // Check if we're in backoff mode from a previous 429
        $backoffUntil = Cache::get(self::BACKOFF_CACHE_KEY);
        if ($backoffUntil && now()->timestamp < $backoffUntil) {
            // During backoff, send a lightweight probe every 5 min to check if quota is restored
            $lastProbe = Cache::get(self::BACKOFF_CACHE_KEY . ':last_probe', 0);
            if (now()->timestamp - $lastProbe < self::PROBE_INTERVAL) {
                return ['error' => true, 'status' => 429, 'backoff' => true];
            }
            Cache::put(self::BACKOFF_CACHE_KEY . ':last_probe', now()->timestamp, self::BACKOFF_DURATION);
        }

        $response = Http::timeout($this->timeout)
            ->withToken($this->apiKey)
            ->post($this->endpoint . '/v1/events', $payload);

        if ($response->status() === 429) {
            $retryAfter = (int) ($response->header('Retry-After') ?: self::BACKOFF_DURATION);
            Cache::put(self::BACKOFF_CACHE_KEY, now()->timestamp + $retryAfter, $retryAfter);
            Log::warning('[SOCWarden] Quota exceeded (429). Backing off for ' . $retryAfter . 's');

            return ['error' => true, 'status' => 429, 'retry_after' => $retryAfter];
        }

        // Clear backoff on any successful response
        if ($response->successful() && $backoffUntil) {
            Cache::forget(self::BACKOFF_CACHE_KEY);
            Cache::forget(self::BACKOFF_CACHE_KEY . ':last_probe');
            Log::info('[SOCWarden] Quota restored, backoff cleared');
        }

        if ($response->failed()) {
            Log::warning('[SOCWarden] Event send failed', [
                'status' => $response->status(),
                'body' => $response->body(),
            ]);

            return ['error' => true, 'status' => $response->status()];
        }

        return $response->json();
    }
}
