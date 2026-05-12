<?php

namespace SOCWarden\Tests\Unit;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;
use Orchestra\Testbench\TestCase;
use SOCWarden\EventBuilder;
use SOCWarden\SOCWardenClient;
use SOCWarden\SOCWardenServiceProvider;

class SOCWardenClientTest extends TestCase
{
    protected function getPackageProviders($app): array
    {
        return [SOCWardenServiceProvider::class];
    }

    /**
     * Define environment setup so the service provider can boot without errors.
     */
    protected function defineEnvironment($app): void
    {
        $app['config']->set('socwarden-sdk.api_key', 'sk_test_abc123');
        $app['config']->set('socwarden-sdk.endpoint', 'https://ingest.test');
        $app['config']->set('socwarden-sdk.timeout', 5);
        $app['config']->set('socwarden-sdk.auto_context', false);
        $app['config']->set('socwarden-sdk.queue', false);
        $app['config']->set('socwarden-sdk.listen_auth_events', false);
    }

    private function makeClient(array $overrides = []): SOCWardenClient
    {
        return new SOCWardenClient(
            apiKey: $overrides['apiKey'] ?? 'sk_test_abc123',
            endpoint: $overrides['endpoint'] ?? 'https://ingest.test',
            timeout: $overrides['timeout'] ?? 5,
            autoContext: $overrides['autoContext'] ?? false,
            useQueue: $overrides['useQueue'] ?? false,
            queueConnection: $overrides['queueConnection'] ?? null,
            queueName: $overrides['queueName'] ?? 'default',
        );
    }

    // -------------------------------------------------------------------------
    //  1. test_track_builds_correct_payload
    // -------------------------------------------------------------------------

    public function test_track_builds_correct_payload(): void
    {
        Http::fake([
            'ingest.test/v1/events' => Http::response(['ok' => true], 202),
        ]);

        $client = $this->makeClient();
        $client->track(
            'auth.login.success',
            actor: 'user_1',
            actorEmail: 'test@example.com',
        );

        Http::assertSent(function ($request) {
            $body = $request->data();

            return $request->url() === 'https://ingest.test/v1/events'
                && $body['event'] === 'auth.login.success'
                && $body['source'] === 'sdk'
                && $body['actor_id'] === 'user_1'
                && $body['actor_email'] === 'test@example.com';
        });
    }

    // -------------------------------------------------------------------------
    //  2. test_track_data_passes_raw_array
    // -------------------------------------------------------------------------

    public function test_track_data_passes_raw_array(): void
    {
        Http::fake([
            'ingest.test/v1/events' => Http::response(['ok' => true], 202),
        ]);

        $client = $this->makeClient();
        $client->trackData('auth.login', ['actor_id' => 'u1']);

        Http::assertSent(function ($request) {
            $body = $request->data();

            return $body['event'] === 'auth.login'
                && $body['source'] === 'sdk'
                && $body['actor_id'] === 'u1';
        });
    }

    // -------------------------------------------------------------------------
    //  3. test_event_builder_chain
    // -------------------------------------------------------------------------

    public function test_event_builder_chain(): void
    {
        $result = (new EventBuilder('x'))
            ->actor('u1')
            ->actorEmail('e@example.com')
            ->meta('k', 'v')
            ->toArray();

        $this->assertSame('x', $result['event']);
        $this->assertSame('u1', $result['actor_id']);
        $this->assertSame('e@example.com', $result['actor_email']);
        $this->assertSame(['k' => 'v'], $result['metadata']);
    }

    // -------------------------------------------------------------------------
    //  4. test_event_builder_send_calls_track_data
    // -------------------------------------------------------------------------

    public function test_event_builder_send_calls_track_data(): void
    {
        Http::fake([
            'ingest.test/v1/events' => Http::response(['ok' => true], 202),
        ]);

        // Register our client in the container so EventBuilder::send() resolves it.
        $client = $this->makeClient();
        $this->app->instance(SOCWardenClient::class, $client);

        (new EventBuilder('auth.logout'))
            ->actor('u99')
            ->meta('reason', 'manual')
            ->send();

        Http::assertSent(function ($request) {
            $body = $request->data();

            return $body['event'] === 'auth.logout'
                && $body['actor_id'] === 'u99'
                && $body['metadata']['reason'] === 'manual';
        });
    }

    // -------------------------------------------------------------------------
    //  5. test_sanitize_query_string
    // -------------------------------------------------------------------------

    public function test_sanitize_query_string(): void
    {
        // sanitizeQueryString is private, so we use reflection to test it.
        $client = $this->makeClient();
        $method = new \ReflectionMethod($client, 'sanitizeQueryString');
        $method->setAccessible(true);

        // Sensitive parameter is redacted, non-sensitive is kept.
        $result = $method->invoke($client, 'token=abc&name=test');
        $this->assertSame('token=[REDACTED]&name=test', $result);

        // Multiple sensitive params.
        $result = $method->invoke($client, 'password=secret&key=123&page=1');
        $this->assertSame('password=[REDACTED]&key=[REDACTED]&page=1', $result);

        // Empty string stays empty.
        $result = $method->invoke($client, '');
        $this->assertSame('', $result);

        // Case-insensitive sensitive detection (paramName is lowercased).
        $result = $method->invoke($client, 'AUTH_TOKEN=xyz&foo=bar');
        $this->assertSame('AUTH_TOKEN=[REDACTED]&foo=bar', $result);
    }

    // -------------------------------------------------------------------------
    //  6. test_429_backoff_sets_cache
    // -------------------------------------------------------------------------

    public function test_429_backoff_sets_cache(): void
    {
        Http::fake([
            'ingest.test/v1/events' => Http::response('Too Many Requests', 429, [
                'Retry-After' => '600',
            ]),
        ]);

        Log::shouldReceive('warning')->atLeast()->once();

        $client = $this->makeClient();
        $client->trackData('auth.login', ['actor_id' => 'u1']);

        // The send method should have written a backoff cache key.
        $this->assertNotNull(Cache::get('socwarden:quota_backoff_until'));
    }

    // -------------------------------------------------------------------------
    //  7. test_resolve_named_args_with_model
    // -------------------------------------------------------------------------

    // -------------------------------------------------------------------------
    //  8. test_invalid_ip_is_stripped
    // -------------------------------------------------------------------------

    public function test_invalid_ip_is_stripped(): void
    {
        Http::fake([
            'ingest.test/v1/events' => Http::response(['ok' => true], 202),
        ]);

        $client = $this->makeClient();
        $client->track('auth.login.success', ip: 'not-an-ip');

        Http::assertSent(function ($request) {
            $body = $request->data();
            $this->assertArrayNotHasKey('ip', $body);
            return true;
        });
    }

    // -------------------------------------------------------------------------
    //  9. test_valid_ip_is_kept
    // -------------------------------------------------------------------------

    public function test_valid_ip_is_kept(): void
    {
        Http::fake([
            'ingest.test/v1/events' => Http::response(['ok' => true], 202),
        ]);

        $client = $this->makeClient();
        $client->track('auth.login.success', ip: '192.168.0.1');

        Http::assertSent(function ($request) {
            $body = $request->data();
            $this->assertSame('192.168.0.1', $body['ip']);
            return true;
        });
    }

    // -------------------------------------------------------------------------
    //  (original 7)

    public function test_resolve_named_args_with_model(): void
    {
        Http::fake([
            'ingest.test/v1/events' => Http::response(['ok' => true], 202),
        ]);

        // Use a concrete Model subclass with attributes set so Eloquent's __get
        // returns the email properly.
        $model = new class extends Model {
            protected $guarded = [];
        };
        $model->forceFill(['id' => 42, 'email' => 'model@example.com']);

        $client = $this->makeClient();
        $client->track('auth.login.success', actor: $model);

        Http::assertSent(function ($request) {
            $body = $request->data();

            return $body['actor_id'] === '42'
                && ($body['actor_email'] ?? null) === 'model@example.com';
        });
    }

    // -------------------------------------------------------------------------
    //  Security: URL-encoded query param bypass in sanitizeQueryString
    // -------------------------------------------------------------------------

    public function test_sanitize_query_string_url_encoded_params_are_redacted(): void
    {
        $client = $this->makeClient();
        $method = new \ReflectionMethod($client, 'sanitizeQueryString');
        $method->setAccessible(true);

        // %74oken is URL-encoded "token" — must be redacted, not passed through.
        $result = $method->invoke($client, '%74oken=mysecret&name=test');
        $this->assertStringContainsString('[REDACTED]', $result);
        $this->assertStringNotContainsString('mysecret', $result);

        // %70assword is "password" — must be redacted.
        $result = $method->invoke($client, '%70assword=hunter2&page=2');
        $this->assertStringContainsString('[REDACTED]', $result);
        $this->assertStringNotContainsString('hunter2', $result);
    }

    // -------------------------------------------------------------------------
    //  Security: metadata denylist strips sensitive keys
    // -------------------------------------------------------------------------

    public function test_sensitive_metadata_keys_are_stripped_from_payload(): void
    {
        Http::fake([
            'ingest.test/v1/events' => Http::response(['ok' => true], 202),
        ]);

        $client = $this->makeClient();
        $client->track('auth.login.success', metadata: [
            'role' => 'admin',
            'password' => 'hunter2',
            'api_key' => 'sk_live_abc',
            'credit_card' => '4111111111111111',
        ]);

        Http::assertSent(function ($request) {
            $body = $request->data();
            $meta = $body['metadata'] ?? [];

            $this->assertArrayHasKey('role', $meta);
            $this->assertArrayNotHasKey('password', $meta);
            $this->assertArrayNotHasKey('api_key', $meta);
            $this->assertArrayNotHasKey('credit_card', $meta);

            return true;
        });
    }

    // -------------------------------------------------------------------------
    //  Security: Retry-After header clamping
    // -------------------------------------------------------------------------

    public function test_retry_after_is_clamped_to_max_value(): void
    {
        Http::fake([
            'ingest.test/v1/events' => Http::response('Too Many Requests', 429, [
                'Retry-After' => '999999999', // attacker-supplied huge value
            ]),
        ]);

        Log::shouldReceive('warning')->atLeast()->once();

        $client = $this->makeClient();
        $client->trackData('auth.login', ['actor_id' => 'u1']);

        $backoffUntil = Cache::get('socwarden:quota_backoff_until');
        $this->assertNotNull($backoffUntil);

        // The backoff timestamp must not be more than MAX_RETRY_AFTER (86400 s) in the future.
        $maxExpected = now()->timestamp + 86400 + 5; // +5 s leeway for test execution time
        $this->assertLessThanOrEqual($maxExpected, $backoffUntil);
    }

    public function test_retry_after_negative_is_clamped_to_minimum(): void
    {
        Http::fake([
            'ingest.test/v1/events' => Http::response('Too Many Requests', 429, [
                'Retry-After' => '-1', // attacker-supplied negative value
            ]),
        ]);

        Log::shouldReceive('warning')->atLeast()->once();

        $client = $this->makeClient();
        $client->trackData('auth.login', ['actor_id' => 'u1']);

        $backoffUntil = Cache::get('socwarden:quota_backoff_until');
        $this->assertNotNull($backoffUntil);

        // Must be at least 1 second in the future (min clamp).
        $this->assertGreaterThan(now()->timestamp, $backoffUntil);
    }

    // -------------------------------------------------------------------------
    //  Security: invalid event types are dropped without sending
    // -------------------------------------------------------------------------

    public function test_invalid_event_type_is_dropped(): void
    {
        Http::fake([
            'ingest.test/v1/events' => Http::response(['ok' => true], 202),
        ]);

        Log::shouldReceive('warning')->once()->with(
            '[SOCWarden] Invalid event type format, dropping event.',
            \Mockery::any()
        );

        $client = $this->makeClient();
        $client->track('INVALID EVENT TYPE!!');

        Http::assertNothingSent();
    }

    // -------------------------------------------------------------------------
    //  Security: response body truncated in failure log
    // -------------------------------------------------------------------------

    public function test_response_body_is_truncated_in_failure_log(): void
    {
        $longBody = str_repeat('x', 500);

        Http::fake([
            'ingest.test/v1/events' => Http::response($longBody, 500),
        ]);

        $loggedBody = null;
        Log::shouldReceive('warning')
            ->once()
            ->withArgs(function (string $msg, array $ctx) use (&$loggedBody) {
                if (str_contains($msg, 'Event send failed')) {
                    $loggedBody = $ctx['body'] ?? null;
                    return true;
                }
                return false;
            });

        $client = $this->makeClient();
        $client->trackData('auth.login', []);

        $this->assertNotNull($loggedBody);
        $this->assertLessThanOrEqual(200, mb_strlen($loggedBody));
    }

    // -------------------------------------------------------------------------
    //  Security: CRLF injection stripped from user_agent and actor_email
    // -------------------------------------------------------------------------

    public function test_crlf_newlines_stripped_from_user_agent(): void
    {
        Http::fake([
            'ingest.test/v1/events' => Http::response(['ok' => true], 202),
        ]);

        $client = $this->makeClient();
        $client->track('auth.login.success', userAgent: "Mozilla/5.0\r\nX-Injected: header");

        Http::assertSent(function ($request) {
            $ua = $request->data()['user_agent'] ?? '';
            $this->assertStringNotContainsString("\r", $ua);
            $this->assertStringNotContainsString("\n", $ua);

            return true;
        });
    }

    public function test_crlf_newlines_stripped_from_actor_email(): void
    {
        Http::fake([
            'ingest.test/v1/events' => Http::response(['ok' => true], 202),
        ]);

        $client = $this->makeClient();
        $client->track('auth.login.success', actorEmail: "alice@example.com\r\nBcc: evil@attacker.com");

        Http::assertSent(function ($request) {
            $email = $request->data()['actor_email'] ?? '';
            $this->assertStringNotContainsString("\r", $email);
            $this->assertStringNotContainsString("\n", $email);

            return true;
        });
    }

    // -------------------------------------------------------------------------
    //  Security: unsupported URL schemes rejected at construction
    // -------------------------------------------------------------------------

    public function test_ftp_scheme_endpoint_throws_at_construction(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessageMatches('/scheme.*ftp.*not allowed/i');

        new SOCWardenClient(
            apiKey: 'sk_test_abc123',
            endpoint: 'ftp://attacker.internal/v1/events',
            timeout: 5,
            autoContext: false,
            useQueue: false,
            queueConnection: null,
            queueName: 'default',
        );
    }

    public function test_empty_api_key_logs_warning(): void
    {
        Log::shouldReceive('warning')
            ->atLeast()->once()
            ->withArgs(fn (string $msg) => str_contains($msg, 'API key is empty'));

        // Also allow the SSRF guard warning that fires for the https://ingest.test
        // hostname resolution in the test environment (environment is 'testing' so
        // the guard is skipped, but the empty-key warning must still fire).
        Log::shouldReceive('warning')->zeroOrMoreTimes();

        new SOCWardenClient(
            apiKey: '',
            endpoint: 'https://ingest.test',
            timeout: 5,
            autoContext: false,
            useQueue: false,
            queueConnection: null,
            queueName: 'default',
        );
    }
}
