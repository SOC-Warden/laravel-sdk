<?php

namespace SOCWarden\Tests\Unit;

use Illuminate\Support\Facades\Http;
use Orchestra\Testbench\TestCase;
use SOCWarden\SOCWardenClient;
use SOCWarden\SOCWardenServiceProvider;

/**
 * Cross-service contract tests verifying the Laravel SDK payload
 * matches the ingestor's expected EventPayload schema.
 */
class ContractTest extends TestCase
{
    /** Ingestor event type regex from ingestor/internal/model/event.go */
    private const EVENT_TYPE_REGEX = '/^[a-z][a-z0-9]{0,29}(\.[a-z][a-z0-9_]{0,29}){1,3}$/';

    /** Fields the ingestor's EventPayload struct accepts (POST /v1/events). */
    private const INGESTOR_ALLOWED_FIELDS = [
        'event',
        'source',
        'actor_id',
        'actor_email',
        'ip',
        'user_agent',
        'metadata',
        'timestamp',
        'context',
    ];

    protected function getPackageProviders($app): array
    {
        return [SOCWardenServiceProvider::class];
    }

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
            browserContextHeader: $overrides['browserContextHeader'] ?? 'X-SOCWarden-Context',
        );
    }

    // -------------------------------------------------------------------------
    //  Contract: track() payload matches ingestor schema
    // -------------------------------------------------------------------------

    public function test_contract_payload_matches_ingestor_schema(): void
    {
        Http::fake([
            'ingest.test/v1/events' => Http::response(['ok' => true], 202),
        ]);

        $client = $this->makeClient();
        $client->track(
            'auth.login.success',
            actorId: 'usr_123',
            actorEmail: 'alice@example.com',
            ip: '10.0.0.1',
            userAgent: 'TestAgent/1.0',
            metadata: ['role' => 'admin'],
            timestamp: '2026-03-18T10:30:00Z',
        );

        Http::assertSent(function ($request) {
            $body = $request->data();

            // Required fields
            $this->assertArrayHasKey('event', $body);
            $this->assertSame('auth.login.success', $body['event']);
            $this->assertMatchesRegularExpression(self::EVENT_TYPE_REGEX, $body['event']);

            $this->assertArrayHasKey('source', $body);
            $this->assertSame('sdk', $body['source']);

            // Optional fields
            $this->assertSame('usr_123', $body['actor_id']);
            $this->assertSame('alice@example.com', $body['actor_email']);
            $this->assertSame('10.0.0.1', $body['ip']);
            $this->assertSame('TestAgent/1.0', $body['user_agent']);
            $this->assertIsArray($body['metadata']);
            $this->assertSame('admin', $body['metadata']['role']);
            $this->assertSame('2026-03-18T10:30:00Z', $body['timestamp']);

            // No unexpected fields
            foreach (array_keys($body) as $key) {
                $this->assertContains(
                    $key,
                    self::INGESTOR_ALLOWED_FIELDS,
                    "Payload contains unexpected field '{$key}' not in ingestor schema"
                );
            }

            return true;
        });
    }

    // -------------------------------------------------------------------------
    //  Contract: minimal payload
    // -------------------------------------------------------------------------

    public function test_contract_minimal_payload(): void
    {
        Http::fake([
            'ingest.test/v1/events' => Http::response(['ok' => true], 202),
        ]);

        $client = $this->makeClient();
        $client->trackData('auth.logout', []);

        Http::assertSent(function ($request) {
            $body = $request->data();

            $this->assertSame('auth.logout', $body['event']);
            $this->assertSame('sdk', $body['source']);

            // No unexpected fields
            foreach (array_keys($body) as $key) {
                $this->assertContains($key, self::INGESTOR_ALLOWED_FIELDS);
            }

            return true;
        });
    }

    // -------------------------------------------------------------------------
    //  Contract: event type format validation
    // -------------------------------------------------------------------------

    public function test_contract_event_type_format(): void
    {
        $events = [
            'auth.login.success',
            'auth.login.failure',
            'auth.logout',
            'auth.mfa.enabled',
            'data.exported',
            'api.request.received',
            'page.view',
        ];

        foreach ($events as $event) {
            $this->assertMatchesRegularExpression(
                self::EVENT_TYPE_REGEX,
                $event,
                "Event '{$event}' does not match ingestor regex"
            );
        }
    }

    // -------------------------------------------------------------------------
    //  Contract: source is always "sdk"
    // -------------------------------------------------------------------------

    public function test_contract_source_is_sdk(): void
    {
        Http::fake([
            'ingest.test/v1/events' => Http::response(['ok' => true], 202),
        ]);

        $client = $this->makeClient();
        $client->track('auth.login.success', actor: 'usr_1');

        Http::assertSent(function ($request) {
            $body = $request->data();
            $this->assertSame('sdk', $body['source']);

            return true;
        });
    }

    // -------------------------------------------------------------------------
    //  Contract: context block structure (when enabled)
    // -------------------------------------------------------------------------

    public function test_contract_context_structure(): void
    {
        Http::fake([
            'ingest.test/v1/events' => Http::response(['ok' => true], 202),
        ]);

        $client = $this->makeClient(['autoContext' => true]);
        $client->track('auth.login.success');

        Http::assertSent(function ($request) {
            $body = $request->data();

            $this->assertArrayHasKey('context', $body);
            $this->assertIsArray($body['context']);
            $this->assertArrayHasKey('sdk', $body['context']);
            $this->assertSame('socwarden-laravel', $body['context']['sdk']['name']);
            $this->assertSame('1.0.0', $body['context']['sdk']['version']);
            $this->assertArrayHasKey('server', $body['context']);

            return true;
        });
    }
}
