<?php

declare(strict_types=1);

namespace Hachitech\Antidetect\Access;

/** Domain result uses Unix seconds; the browser serializer converts to milliseconds. */
final class AccessDecision
{
    private function __construct(
        public readonly string $status,
        public readonly int $expiresAt = 0,
        public readonly int $passDuration = 0,
        public readonly string $verification = '',
        public readonly int $retryAfterSeconds = 0,
        public readonly ?string $verificationId = null
    ) {
    }

    public static function pending(?string $verificationId = null, int $until = 0): self
    {
        return new self('verification_required', $until, verificationId: $verificationId);
    }

    public static function failed(?string $verificationId = null): self
    {
        return new self('verification_failed', verificationId: $verificationId);
    }

    public static function disabled(): self
    {
        return new self('disabled');
    }

    public static function allowed(
        int $until,
        int $passDuration,
        string $verification,
        ?string $verificationId = null
    ): self {
        return new self('allowed', $until, $passDuration, $verification, verificationId: $verificationId);
    }

    public static function blocked(int $until, int $now): self
    {
        return new self('blocked', $until, retryAfterSeconds: max(0, $until - $now));
    }

    /** @return array<string, bool|int|string> */
    public function toBrowserArray(): array
    {
        $data = match ($this->status) {
            'allowed' => [
                'status' => 'allowed', 'allowed' => true, 'expiresAt' => $this->expiresAt * 1000,
                'passDuration' => $this->passDuration, 'verification' => $this->verification,
            ],
            'blocked' => [
                'status' => 'blocked', 'blocked' => true, 'blockedUntil' => $this->expiresAt * 1000,
                'retryAfterMs' => $this->retryAfterSeconds * 1000,
            ],
            default => ['status' => $this->status],
        };
        if ($this->verificationId !== null) {
            $data['verificationId'] = $this->verificationId;
            if ($this->status === 'verification_required') {
                $data['verificationUntil'] = $this->expiresAt * 1000;
            }
        }
        return $data;
    }
}
