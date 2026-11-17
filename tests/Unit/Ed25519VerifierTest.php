<?php

declare(strict_types=1);

namespace Hachitechs\HideguardPhp\Tests\Unit;

use Hachitechs\HideguardPhp\Access\AccessContext;
use Hachitechs\HideguardPhp\Configuration\ProtectionPolicy;
use Hachitechs\HideguardPhp\Exceptions\FailureReason;
use Hachitechs\HideguardPhp\Exceptions\GuardException;
use Hachitechs\HideguardPhp\Guard;
use Hachitechs\HideguardPhp\Tests\Support\FrozenClock;
use Hachitechs\HideguardPhp\Tests\Support\MemoryStorage;
use Hachitechs\HideguardPhp\Tests\Support\SignedVerdictFixture;
use Hachitechs\HideguardPhp\Verification\Ed25519Verifier;
use Hachitechs\HideguardPhp\Verification\VerdictPolicy;
use PHPUnit\Framework\TestCase;

final class Ed25519VerifierTest extends TestCase
{
    private const SIGNED_AT = 1791800431;

    private static function vectors(): array
    {
        return json_decode(
            file_get_contents(dirname(__DIR__) . '/Fixtures/hideguard-ed25519-v2.json'),
            true,
            512,
            JSON_THROW_ON_ERROR
        );
    }

    private function policy(int $passDuration = 300): ProtectionPolicy
    {
        return new ProtectionPolicy(
            enabled: true,
            publicKey: 'site-key',
            signaturePublicKey: self::vectors()['generated']['publicKey'],
            passDuration: $passDuration,
            blockDuration: 900
        );
    }

    /** @dataProvider signedResponses */
    public function testSignedResponsesVerifyWithoutSelectingAnEnvironment(array $payload): void
    {
        $verifier = new Ed25519Verifier(new FrozenClock(self::SIGNED_AT + 1));
        $result = $verifier->verify(
            $payload,
            new AccessContext('site', 'browser'),
            $this->policy()
        );
        $expected = in_array($payload['verdict'], VerdictPolicy::BLOCK_VERDICTS, true) ? 'block' : 'allow';
        self::assertSame($expected, $result->verdict);
        self::assertSame($payload['visitorId'], $result->visitorId);
        self::assertSame(self::SIGNED_AT, $result->issuedAt);
        self::assertTrue($result->verified);
    }

    public static function signedResponses(): array
    {
        return array_map(fn(array $payload) => [$payload], self::vectors()['generated']['responses']);
    }

    public function testUnknownSignedEnvironmentDoesNotRequireConfiguration(): void
    {
        $payload = SignedVerdictFixture::payload(environment: 'any-signed-value');
        $policy = new ProtectionPolicy(
            enabled: true,
            publicKey: 'site-key',
            signaturePublicKey: SignedVerdictFixture::publicKey()
        );
        $result = (new Ed25519Verifier())->verify($payload, new AccessContext('site', 'browser'), $policy);
        self::assertTrue($result->verified);
        self::assertSame('allow', $result->verdict);
    }

    public function testDefaultPolicyAuthorizesASignedProductionVerdict(): void
    {
        $vectors = self::vectors()['generated'];
        $payload = array_values(array_filter(
            $vectors['responses'],
            fn(array $response) => $response['environment'] === 'production' && $response['verdict'] === 'allow'
        ))[0];
        $policy = new ProtectionPolicy(
            enabled: true,
            publicKey: 'site-key',
            signaturePublicKey: $vectors['publicKey']
        );
        $clock = new FrozenClock(self::SIGNED_AT + 1);
        $guard = Guard::factory()->withStorage(new MemoryStorage())->withClock($clock)
            ->withVerifier(new Ed25519Verifier($clock))->make();
        $context = new AccessContext('site', 'browser');
        $pending = $guard->preflight($context, $policy);
        $decision = $guard->report($context, $policy, $payload, $pending->verificationId);

        self::assertSame('allowed', $decision->status);
        self::assertSame('verified', $decision->verification);
        self::assertSame('allowed', $guard->inspect($context, $policy)->status);
    }

    public function testRealHideGuardVectorMatchesShopifyAndIgnoresUnsignedDisplayFields(): void
    {
        $vector = self::vectors()['real'];
        $vector['payload']['reasons'][0]['detail'] = 'Different display text';
        $policy = new ProtectionPolicy(
            enabled: true,
            publicKey: 'key',
            signaturePublicKey: $vector['publicKey']
        );
        $result = (new Ed25519Verifier(new FrozenClock(self::SIGNED_AT + 1)))
            ->verify($vector['payload'], new AccessContext('site', 'browser'), $policy);
        self::assertSame('allow', $result->verdict);
        self::assertTrue($result->verified);
    }

    /** @dataProvider invalidResponses */
    public function testTamperingAndMalformedSignedFieldsAreRejected(array $payload): void
    {
        $this->expectException(GuardException::class);
        $this->expectExceptionMessageMatches('/Invalid HideGuard/');
        (new Ed25519Verifier(new FrozenClock(self::SIGNED_AT + 1)))
            ->verify($payload, new AccessContext('site', 'browser'), $this->policy());
    }

    public static function invalidResponses(): array
    {
        $original = self::vectors()['generated']['responses'][6];
        $cases = [[[]]];
        foreach (
            [
            'siteId' => 'other-site', 'requestId' => 'other-request', 'visitorId' => 'other-visitor',
            'verdict' => 'block', 'score' => 0, 'environment' => 'staging', 'signature' => '',
            'reasons' => [['code' => 'changed']],
            ] as $field => $value
        ) {
            $cases[] = [array_replace($original, [$field => $value])];
        }
        foreach (
            [
            ['score' => -1], ['score' => '35'], ['score' => 1.5], ['score' => 9007199254740992],
            ['siteId' => "site\nother"], ['visitorId' => ''], ['requestId' => str_repeat('a', 129)],
            ['environment' => null], ['environment' => []], ['environment' => "value\nsite=other"],
            ['verdict' => 'unknown'], ['reasons' => ['code' => 'not-a-list']],
            ['reasons' => array_fill(0, 65, ['code' => 'reason'])], ['reasons' => [['code' => "bad\ncode"]]],
            ['reasons' => [null]],
            ] as $change
        ) {
            $cases[] = [array_replace($original, $change)];
        }
        foreach (['v=2' => 'v=1', 'alg=ed25519' => 'alg=rsa', 'kid=hg_test' => 'kid=other'] as $from => $to) {
            $cases[] = [array_replace($original, ['signature' => str_replace($from, $to, $original['signature'])])];
        }
        $cases[] = [array_replace($original, ['signature' => $original['signature'] . "\n"])];
        $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
        $last = strpos($alphabet, substr($original['signature'], -1));
        $nonCanonical = substr($original['signature'], 0, -1) . $alphabet[$last + 1];
        $cases[] = [array_replace($original, ['signature' => $nonCanonical])];
        return $cases;
    }

    public function testSignatureFromAnotherKeyCannotAuthorize(): void
    {
        $payload = self::vectors()['generated']['responses'][6];
        $policy = new ProtectionPolicy(
            enabled: true,
            publicKey: 'key',
            signaturePublicKey: self::vectors()['real']['publicKey']
        );
        $this->expectException(GuardException::class);
        $this->expectExceptionMessage('Invalid HideGuard response signature.');
        (new Ed25519Verifier(new FrozenClock(self::SIGNED_AT + 1)))
            ->verify($payload, new AccessContext('site', 'browser'), $policy);
    }

    /** @dataProvider invalidKeys */
    public function testOnlyCanonicalEd25519SpkiPublicKeysAreAccepted(string $key): void
    {
        $this->expectException(GuardException::class);
        Ed25519Verifier::validatePublicKey($key);
    }

    public static function invalidKeys(): array
    {
        $pem = self::vectors()['real']['publicKey'];
        return [[''], ['not-a-key'], [str_replace('PUBLIC KEY', 'PRIVATE KEY', $pem)],
            [str_replace('MCow', 'MCsw', $pem)], [$pem . 'trailing-data'], [str_repeat('x', 4097)]];
    }

    /** @dataProvider timing */
    public function testFreshnessUsesThePassPresetAndAllowsAtMostThirtySecondsOfClockSkew(
        int $duration,
        int $age,
        bool $valid
    ): void {
        $verifier = new Ed25519Verifier(new FrozenClock(self::SIGNED_AT + $age));
        if (!$valid) {
            $this->expectException(GuardException::class);
        }
        $result = $verifier->verify(
            self::vectors()['generated']['responses'][6],
            new AccessContext('site', 'browser'),
            $this->policy(passDuration: $duration)
        );
        self::assertTrue($result->verified);
    }

    public static function timing(): array
    {
        return [[0, 299, true], [0, 300, false], [60, 59, true], [60, 60, false],
            [300, -30, true], [300, -31, false], [900, 899, true], [900, 900, false],
            [3600, 3599, true], [3600, 3600, false]];
    }

    public function testGuardBoundsGrantsBySignedTimeAndCommitsRevocationOnRejectedReplay(): void
    {
        $clock = new FrozenClock(self::SIGNED_AT + 100);
        $guard = Guard::factory()->withStorage(new MemoryStorage())->withClock($clock)
            ->withVerifier(new Ed25519Verifier($clock))->make();
        $context = new AccessContext('site', 'browser');
        $policy = $this->policy();
        $payload = self::vectors()['generated']['responses'][6];
        $verificationId = $guard->preflight($context, $policy)->verificationId;
        self::assertSame(
            self::SIGNED_AT + 300,
            $guard->report($context, $policy, $payload, $verificationId)->expiresAt
        );
        $clock->timestamp += 100;
        self::assertSame(
            self::SIGNED_AT + 300,
            $guard->report($context, $policy, $payload, $verificationId)->expiresAt
        );
        $payload['score'] = 0;
        try {
            $guard->report($context, $policy, $payload, $verificationId);
            self::fail('Tampering must revoke the stored pass.');
        } catch (GuardException $error) {
            self::assertSame(FailureReason::InvalidVerdict, $error->reason);
        }
        self::assertSame('verification_failed', $guard->inspect($context, $policy)->status);
        $clock->timestamp = self::SIGNED_AT + 300;
        $this->expectException(GuardException::class);
        $payload = self::vectors()['generated']['responses'][6];
        $verificationId = $guard->preflight($context, $policy, true)->verificationId;
        $guard->report($context, $policy, $payload, $verificationId);
    }

    public function testPersistedBlockSkipsExpiredSignaturesButReplayCannotStartANewBanAfterExpiry(): void
    {
        $clock = new FrozenClock(self::SIGNED_AT + 10);
        $guard = Guard::factory()->withStorage(new MemoryStorage())->withClock($clock)
            ->withVerifier(new Ed25519Verifier($clock))->make();
        $context = new AccessContext('site', 'browser');
        $policy = $this->policy(passDuration: 3600);
        $payload = self::vectors()['generated']['responses'][8];
        $verificationId = $guard->preflight($context, $policy)->verificationId;
        self::assertSame(
            self::SIGNED_AT + 900,
            $guard->report($context, $policy, $payload, $verificationId)->expiresAt
        );
        $clock->timestamp = self::SIGNED_AT + 899;
        self::assertSame('blocked', $guard->report($context, $policy, [], $verificationId)->status);
        $clock->timestamp++;
        $this->expectException(GuardException::class);
        $guard->report($context, $policy, $payload, $verificationId);
    }

    public function testOldPolicyFingerprintCannotReuseAnUnsignedStoredPass(): void
    {
        $policy = $this->policy();
        $settings = get_object_vars($policy);
        sort($settings['accessPoints']);
        sort($settings['pageRules']);
        self::assertNotSame(hash('sha256', json_encode($settings, JSON_THROW_ON_ERROR)), $policy->fingerprint());
    }
}
