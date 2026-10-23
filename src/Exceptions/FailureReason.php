<?php

declare(strict_types=1);

namespace Hachitechs\HideguardPhp\Exceptions;

enum FailureReason: string
{
    case InvalidConfiguration = 'invalid_configuration';
    case InvalidIdentity = 'invalid_identity';
    case Disabled = 'disabled';
    case InvalidVerdict = 'invalid_verdict';
    case VerificationUnavailable = 'verification_unavailable';
    case PermissionDenied = 'permission_denied';
    case RateLimited = 'rate_limited';
    case CapacityReached = 'capacity_reached';
    case Busy = 'busy';
}
