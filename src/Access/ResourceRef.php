<?php

declare(strict_types=1);

namespace Hachitechs\HideguardPhp\Access;

/** Resource ownership is supplied by the server; null identifies a guest resource. */
final class ResourceRef
{
    public function __construct(
        public readonly string $type,
        public readonly string $id,
        public readonly ?string $actorId = null
    ) {
        AccessContext::validateId($type);
        AccessContext::validateId($id);
        if ($actorId !== null) {
            AccessContext::validateId($actorId);
        }
    }
}
