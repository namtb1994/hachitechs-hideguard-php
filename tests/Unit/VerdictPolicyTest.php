<?php

declare(strict_types=1);

namespace Hachitech\Antidetect\Tests\Unit;

use Hachitech\Antidetect\Verification\VerdictPolicy;
use PHPUnit\Framework\TestCase;

final class VerdictPolicyTest extends TestCase
{
    /** @dataProvider verdicts */
    public function testVerdictsAreClassifiedUsingStrictGroupMembership(mixed $verdict, ?string $expected): void
    {
        self::assertSame($expected, VerdictPolicy::groupFor($verdict));
    }

    public static function verdicts(): array
    {
        return [
            ['block', 'block'], ['challenge', 'challenge'], ['allow', 'allow'],
            ['unknown', null], ['ALLOW', null], ['', null], ['allow ', null],
            [true, null], [1, null], [null, null], [['allow'], null],
        ];
    }
}
