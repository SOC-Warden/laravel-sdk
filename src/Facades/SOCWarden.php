<?php

namespace SOCWarden\Facades;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\Facade;
use SOCWarden\EventBuilder;
use SOCWarden\SOCWardenClient;

/**
 * @method static EventBuilder event(string $event)
 * @method static void track(string $event, Model|string|null $actor = null, ?string $actorId = null, ?string $actorEmail = null, ?string $ip = null, ?string $userAgent = null, ?array $metadata = null, \DateTimeInterface|string|null $timestamp = null, Model|string|null $resource = null, string|int|null $resourceId = null)
 * @method static void trackData(string $event, array $data = [])
 *
 * @see SOCWardenClient
 */
class SOCWarden extends Facade
{
    protected static function getFacadeAccessor(): string
    {
        return SOCWardenClient::class;
    }
}
