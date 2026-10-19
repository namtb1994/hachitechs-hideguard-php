<?php

declare(strict_types=1);

namespace Hachitech\Antidetect\Verification;

/** Local verdict groups using the structure of HideGuard's shared/verdict-policy.json. */
final class VerdictPolicy
{
    public const BLOCK_VERDICTS = ['block', 'challenge'];
    public const CHALLENGE_VERDICTS = [];
    public const ALLOW_VERDICTS = ['allow'];

    public static function groupFor(mixed $verdict): ?string
    {
        $groups = [
            'block' => self::BLOCK_VERDICTS,
            'challenge' => self::CHALLENGE_VERDICTS,
            'allow' => self::ALLOW_VERDICTS,
        ];
        foreach ($groups as $group => $verdicts) {
            if (in_array($verdict, $verdicts, true)) {
                return $group;
            }
        }
        return null;
    }
}
