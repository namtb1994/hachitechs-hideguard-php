<?php

declare(strict_types=1);

namespace Hachitechs\HideguardPhp\Tests\Support;

/** Independent signer with a fixed test-only key, used by executable example tests. */
final class SignedVerdictFixture
{
    private static function keyPair(): string
    {
        return sodium_crypto_sign_seed_keypair(str_repeat("\x01", SODIUM_CRYPTO_SIGN_SEEDBYTES));
    }

    public static function publicKey(): string
    {
        $der = hex2bin('302a300506032b6570032100') . sodium_crypto_sign_publickey(self::keyPair());
        return "-----BEGIN PUBLIC KEY-----\n" . base64_encode($der) . "\n-----END PUBLIC KEY-----";
    }

    /** @return array<string, mixed> */
    public static function payload(
        string $verdict = 'allow',
        string $visitorId = 'web-visitor',
        string $environment = 'production'
    ): array {
        $now = time();
        $payload = [
            'siteId' => 'test-site', 'requestId' => 'test-request', 'visitorId' => $visitorId,
            'environment' => $environment, 'verdict' => $verdict, 'score' => 10, 'reasons' => [],
        ];
        $message = implode("\n", [
            'hideguard-collect-ed25519-v2', 'alg=ed25519', 'kid=fixture', 't=' . $now,
            'site=' . $payload['siteId'], 'environment=' . $payload['environment'],
            'request=' . $payload['requestId'], 'visitor=' . $visitorId,
            'verdict=' . $verdict, 'score=10', 'reasons=[]',
        ]);
        $signature = sodium_crypto_sign_detached($message, sodium_crypto_sign_secretkey(self::keyPair()));
        $payload['signature'] = 'v=2,alg=ed25519,kid=fixture,t=' . $now . ',sig='
            . rtrim(strtr(base64_encode($signature), '+/', '-_'), '=');
        return $payload;
    }
}
