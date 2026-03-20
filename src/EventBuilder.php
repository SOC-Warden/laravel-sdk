<?php

namespace SOCWarden;

use Illuminate\Database\Eloquent\Model;

class EventBuilder
{
    private string $event;
    private array $data = [];

    public function __construct(string $event)
    {
        $this->event = $event;
    }

    /**
     * Set the actor (user) who triggered the event.
     *
     * Accepts a user model (reads id + email), a string ID, or separate id/email.
     *
     *   ->actor($user)
     *   ->actor('usr_123')
     *   ->actor('usr_123', 'john@example.com')
     */
    public function actor(Model|string $actor, ?string $email = null): static
    {
        if ($actor instanceof Model) {
            $this->data['actor_id'] = (string) $actor->getKey();
            $this->data['actor_email'] = $actor->email ?? $email;
        } else {
            $this->data['actor_id'] = $actor;
            if ($email !== null) {
                $this->data['actor_email'] = $email;
            }
        }

        return $this;
    }

    /**
     * Set the actor ID directly.
     */
    public function actorId(string $id): static
    {
        $this->data['actor_id'] = $id;

        return $this;
    }

    /**
     * Set the actor email directly.
     */
    public function actorEmail(string $email): static
    {
        $this->data['actor_email'] = $email;

        return $this;
    }

    /**
     * Set the source IP address (auto-detected if not set).
     */
    public function ip(string $ip): static
    {
        $this->data['ip'] = $ip;

        return $this;
    }

    /**
     * Set the user agent string (auto-detected if not set).
     */
    public function userAgent(string $ua): static
    {
        $this->data['user_agent'] = $ua;

        return $this;
    }

    /**
     * Set custom metadata. Merges with any previously set metadata.
     *
     *   ->metadata(['role' => 'admin', 'action' => 'export'])
     *   ->meta('role', 'admin')  // alias for single key
     */
    public function metadata(array $metadata): static
    {
        $this->data['metadata'] = array_merge($this->data['metadata'] ?? [], $metadata);

        return $this;
    }

    /**
     * Set a single metadata key-value pair.
     *
     *   ->meta('role', 'admin')
     */
    public function meta(string $key, mixed $value): static
    {
        $this->data['metadata'] ??= [];
        $this->data['metadata'][$key] = $value;

        return $this;
    }

    /**
     * Set the event timestamp (ISO 8601 string or Carbon instance).
     */
    public function timestamp(\DateTimeInterface|string $timestamp): static
    {
        $this->data['timestamp'] = $timestamp instanceof \DateTimeInterface
            ? $timestamp->format('c')
            : $timestamp;

        return $this;
    }

    /**
     * Set the event severity hint for the enricher.
     */
    public function severity(string $severity): static
    {
        $this->data['metadata'] ??= [];
        $this->data['metadata']['_severity'] = $severity;

        return $this;
    }

    /**
     * Attach the resource that was acted upon.
     *
     *   ->resource('Order', $order->id)
     *   ->resource($order)  // reads class name + key
     */
    public function resource(Model|string $type, string|int|null $id = null): static
    {
        $this->data['metadata'] ??= [];

        if ($type instanceof Model) {
            $this->data['metadata']['resource_type'] = class_basename($type);
            $this->data['metadata']['resource_id'] = (string) $type->getKey();
        } else {
            $this->data['metadata']['resource_type'] = $type;
            if ($id !== null) {
                $this->data['metadata']['resource_id'] = (string) $id;
            }
        }

        return $this;
    }

    /**
     * Send the event.
     */
    public function send(): void
    {
        app(SOCWardenClient::class)->trackData($this->event, $this->data);
    }

    /**
     * Get the built data array (for testing/inspection).
     */
    public function toArray(): array
    {
        return array_merge(['event' => $this->event], $this->data);
    }
}
