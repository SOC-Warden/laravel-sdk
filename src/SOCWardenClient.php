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

    /** Maximum Retry-After value accepted from the server (24 h). Prevents DoS via crafted headers. */
    private const MAX_RETRY_AFTER = 86400;

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
    ) {
        // D2 FIX: Enforce HTTPS to prevent API key transmission in cleartext.
        if (str_starts_with($this->endpoint, 'http://')) {
            if (app()->environment('production')) {
                throw new \InvalidArgumentException(
                    '[SOCWarden] Endpoint must use HTTPS in production. API keys must not be transmitted in cleartext.'
                );
            }
            Log::warning('[SOCWarden] WARNING: Endpoint is using HTTP. API keys will be transmitted in cleartext.');
        }

        // SSRF guard: reject endpoints that resolve to private/loopback addresses.
        // The API key is sent with every request; allowing an attacker-supplied
        // internal endpoint would expose it to services on the internal network.
        $this->assertEndpointNotInternal($this->endpoint);
    }

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
        // D3 FIX: Validate event_type format before sending to the ingestor.
        if (! $this->isValidEventType($event)) {
            Log::warning('[SOCWarden] Invalid event type format, dropping event.', ['event' => $event]);
            return;
        }

        $payload = $this->buildPayload($event, $data);

        if ($this->useQueue) {
            // Capture only the scalar payload — do NOT capture $this.
            // Capturing $this would serialize the entire SOCWardenClient instance,
            // including the plaintext API key, into the queue backend (Redis/DB).
            // Instead, the queued closure resolves a fresh client from the container.
            dispatch(function () use ($payload): void {
                app(self::class)->send($payload);
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

    /** Metadata keys that must never be forwarded to the ingestor. */
    private const METADATA_DENYLIST = ['password', 'passwd', 'secret', 'api_key', 'token', 'credit_card', 'cvv', 'ssn'];

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

        // Strip any sensitive keys that callers may have accidentally included in metadata.
        if (isset($payload['metadata']) && is_array($payload['metadata'])) {
            $payload['metadata'] = $this->redactMetadata($payload['metadata']);
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
                // PID omitted: exposing the process ID allows an attacker to correlate
                // requests across events to fingerprint the Octane/FrankenPHP worker pool
                // and aids timing-based process enumeration attacks.
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

            // D1 FIX: X-SOCWarden-Context header removed — trusting arbitrary HTTP headers
            // allows any client to spoof server-side metadata. Server context is collected
            // locally by the SDK at initialization and must not be merged from request headers.
        }

        return $context;
    }

    /**
     * Remove well-known sensitive keys from a metadata array.
     * This is a last-resort safety net for developers who accidentally pass
     * credentials or PII directly into the metadata bag.
     *
     * @param  array<string, mixed>  $metadata
     * @return array<string, mixed>
     */
    private function redactMetadata(array $metadata): array
    {
        return array_filter(
            $metadata,
            fn (string $key) => ! $this->isSensitiveMetadataKey($key),
            ARRAY_FILTER_USE_KEY,
        );
    }

    private function isSensitiveMetadataKey(string $key): bool
    {
        $normalized = strtolower($key);
        foreach (self::METADATA_DENYLIST as $denied) {
            if (str_contains($normalized, $denied)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Validate the event type against the ingestor's required format.
     * Pattern: ^[a-z][a-z0-9]{0,29}(\.[a-z][a-z0-9_]{0,29}){1,3}$
     */
    private function isValidEventType(string $event): bool
    {
        return (bool) preg_match('/^[a-z][a-z0-9]{0,29}(\.[a-z][a-z0-9_]{0,29}){1,3}$/', $event);
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
            // URL-decode the parameter name before matching so that percent-encoded
            // variants like %74oken are not silently passed through unredacted.
            $paramName = strtolower(urldecode($kv[0]));
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

    /**
     * Reject endpoints that point to RFC-1918 private ranges, loopback, link-local,
     * or cloud metadata addresses to prevent SSRF via misconfigured SOCWARDEN_ENDPOINT.
     *
     * This check is intentionally skipped in the `testing` environment so that
     * Orchestra Testbench tests can use fake hostnames like `ingest.test`.
     */
    private function assertEndpointNotInternal(string $endpoint): void
    {
        // Skip SSRF guard in test environments where fake hostnames are used.
        if (app()->environment('testing')) {
            return;
        }

        $parsed = parse_url($endpoint);
        $host = $parsed['host'] ?? '';

        if ($host === '') {
            throw new \InvalidArgumentException('[SOCWarden] Endpoint has no valid host.');
        }

        // Resolve the hostname to an IP for range checking.
        $ip = filter_var($host, FILTER_VALIDATE_IP) !== false
            ? $host
            : gethostbyname($host);

        // Disallow private, loopback, link-local, and cloud-metadata ranges.
        $blockedRanges = [
            '10.0.0.0/8',       // RFC-1918 class A
            '172.16.0.0/12',    // RFC-1918 class B
            '192.168.0.0/16',   // RFC-1918 class C
            '127.0.0.0/8',      // IPv4 loopback
            '169.254.0.0/16',   // link-local / EC2 IMDS
            '100.64.0.0/10',    // Shared address space (RFC 6598)
            '::1/128',          // IPv6 loopback
            'fc00::/7',         // IPv6 ULA
            'fe80::/10',        // IPv6 link-local
        ];

        foreach ($blockedRanges as $cidr) {
            if ($this->ipInCidr($ip, $cidr)) {
                throw new \InvalidArgumentException(
                    "[SOCWarden] Endpoint '{$endpoint}' resolves to a private/internal address. SSRF prevented."
                );
            }
        }
    }

    private function ipInCidr(string $ip, string $cidr): bool
    {
        [$range, $mask] = explode('/', $cidr);

        // IPv6
        if (str_contains($range, ':')) {
            if (! filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
                return false;
            }
            $ipBin = inet_pton($ip);
            $rangeBin = inet_pton($range);
            if ($ipBin === false || $rangeBin === false) {
                return false;
            }
            $maskBytes = (int) floor((int) $mask / 8);
            $maskBits = (int) $mask % 8;
            if (substr($ipBin, 0, $maskBytes) !== substr($rangeBin, 0, $maskBytes)) {
                return false;
            }
            if ($maskBits > 0 && $maskBytes < strlen($rangeBin)) {
                $m = 0xFF & (0xFF << (8 - $maskBits));
                return (ord($ipBin[$maskBytes]) & $m) === (ord($rangeBin[$maskBytes]) & $m);
            }

            return true;
        }

        // IPv4
        if (! filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            return false;
        }

        $ipLong = ip2long($ip);
        $rangeLong = ip2long($range);
        if ($ipLong === false || $rangeLong === false) {
            return false;
        }
        $maskLong = ~((1 << (32 - (int) $mask)) - 1);

        return ($ipLong & $maskLong) === ($rangeLong & $maskLong);
    }

    /** @internal Called directly by queued closures via app(self::class)->send(). */
    public function send(array $payload): array
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
            // Clamp Retry-After to a safe range: minimum 1 s, maximum 24 h.
            // An attacker-controlled ingestor (or MITM) could otherwise supply a
            // negative value (no backoff) or an astronomically large value (permanent DoS).
            $rawRetryAfter = (int) ($response->header('Retry-After') ?: self::BACKOFF_DURATION);
            $retryAfter = max(1, min($rawRetryAfter, self::MAX_RETRY_AFTER));
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
            // Truncate the response body to 200 characters to avoid flooding logs
            // with potentially sensitive ingestor error details or stack traces.
            Log::warning('[SOCWarden] Event send failed', [
                'status' => $response->status(),
                'body' => mb_substr($response->body(), 0, 200),
            ]);

            return ['error' => true, 'status' => $response->status()];
        }

        return $response->json();
    }
}
