<?php

declare(strict_types=1);

namespace Hachitechs\HideguardPhp\Tests\Unit;

use Hachitechs\HideguardPhp\Access\AccessContext;
use Hachitechs\HideguardPhp\Configuration\ProtectionPolicy;
use Hachitechs\HideguardPhp\Contracts\VerdictVerifier;
use Hachitechs\HideguardPhp\Exceptions\GuardException;
use Hachitechs\HideguardPhp\Guard;
use Hachitechs\HideguardPhp\Tests\Support\FrozenClock;
use Hachitechs\HideguardPhp\Tests\Support\MemoryStorage;
use Hachitechs\HideguardPhp\Verification\PrivateVerdictChecker;
use Hachitechs\HideguardPhp\Verification\VerifiedVerdict;
use PHPUnit\Framework\TestCase;

final class PrivateVerdictCheckerTest extends TestCase
{
    /** @dataProvider verdicts */
    public function testAuthenticatedPrivateVerdictsUseServerTimeAndCurrentPolicy(string $verdict, string $status): void
    {
        $clock = new FrozenClock();
        $checker = new PrivateVerdictChecker($clock);
        $payload = ['visitorId' => 'visitor', 'verdict' => $verdict, 'score' => 10,
            'reasons' => [['code' => 'reason', 'detail' => null]]];
        $checked = $checker->check($payload, 'visitor');
        self::assertSame($verdict, $checked->verdict);
        self::assertTrue($checked->verified);
        self::assertSame(1000, $checked->issuedAt);
        $verifier = new class ($checker) implements VerdictVerifier {
            public function __construct(private readonly PrivateVerdictChecker $checker)
            {
            }
            public function verify(array $payload, AccessContext $context, ProtectionPolicy $policy): VerifiedVerdict
            {
                return $this->checker->check($payload, 'visitor');
            }
        };
        $guard = Guard::factory()->withStorage(new MemoryStorage())->withClock($clock)->withVerifier($verifier)->make();
        $context = new AccessContext('scope', 'browser');
        $policy = new ProtectionPolicy(
            enabled: true,
            environment: 'production',
            publicKey: 'key',
            signaturePublicKey: 'key'
        );
        $attempt = $guard->preflight($context, $policy);
        self::assertSame($status, $guard->report($context, $policy, $payload, $attempt->verificationId)->status);
    }

    public static function verdicts(): array
    {
        return [['allow', 'allowed'], ['challenge', 'allowed'], ['block', 'blocked']];
    }

    /** @dataProvider invalidResponses */
    public function testInvalidPrivateResponseCannotProduceAVerifiedVerdict(array $replace): void
    {
        $this->expectException(GuardException::class);
        (new PrivateVerdictChecker(new FrozenClock()))->check(array_replace(
            ['visitorId' => 'visitor', 'verdict' => 'allow', 'score' => 0, 'reasons' => []],
            $replace
        ), 'visitor');
    }

    public static function invalidResponses(): array
    {
        return [
            [['visitorId' => 'other']], [['visitorId' => '']], [['visitorId' => "visitor\n"]],
            [['verdict' => 'unknown']], [['verdict' => ['allow']]], [['score' => '0']], [['score' => -1]],
            [['score' => 9007199254740992]], [['reasons' => null]], [['reasons' => ['key' => []]]],
            [['reasons' => [null]]], [['reasons' => [['code' => '']]]], [['reasons' => [['code' => "bad\ncode"]]]],
            [['reasons' => array_fill(0, 65, ['code' => 'reason'])]],
        ];
    }

    public function testMaximumReasonListAndSafeIntegerScoreAreAccepted(): void
    {
        $checked = (new PrivateVerdictChecker(new FrozenClock()))->check([
            'visitorId' => 'visitor', 'verdict' => 'allow', 'score' => 9007199254740991,
            'reasons' => array_fill(0, 64, ['code' => 'reason']),
        ], 'visitor');
        self::assertSame('allow', $checked->verdict);
    }
}
