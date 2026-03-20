<?php

namespace SOCWarden\Middleware;

use Closure;
use Illuminate\Http\Request;
use SOCWarden\SOCWardenClient;

class CaptureContext
{
    public function __construct(private SOCWardenClient $client) {}

    public function handle(Request $request, Closure $next): mixed
    {
        $this->client->setRequest($request);
        return $next($request);
    }
}
