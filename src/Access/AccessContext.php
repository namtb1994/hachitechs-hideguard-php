<?php

declare(strict_types=1);

namespace Hachitechs\HideguardPhp\Access;

use Hachitechs\HideguardPhp\Exceptions\FailureReason;
use Hachitechs\HideguardPhp\Exceptions\GuardException;

/** All IDs must come from trusted application state, never arbitrary browser input. */
final class AccessContext
{
    public function __construct(
        public readonly string $scopeId,
        public readonly string $browserId,
        public readonly ?string $actorId = null
    ) {
        self::validateId($scopeId);
        self::validateId($browserId);
        if ($actorId !== null) {
            self::validateId($actorId);
        }
    }

    public static function validateId(string $id): void
    {
        if ($id === '' || strlen($id) > 128 || str_contains($id, "\0")) {
            throw new GuardException(FailureReason::InvalidIdentity, 'IDs must contain 1 to 128 bytes without NUL.');
        }
    }
}
