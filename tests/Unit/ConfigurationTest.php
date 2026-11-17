<?php

declare(strict_types=1);

namespace Hachitechs\HideguardPhp\Tests\Unit;

use Hachitechs\HideguardPhp\Access\AccessContext;
use Hachitechs\HideguardPhp\Configuration\ProtectionPolicy;
use Hachitechs\HideguardPhp\Configuration\RateLimits;
use Hachitechs\HideguardPhp\Exceptions\FailureReason;
use Hachitechs\HideguardPhp\Exceptions\GuardException;
use Hachitechs\HideguardPhp\Guard;
use Hachitechs\HideguardPhp\Rules\PathMatcher;
use PHPUnit\Framework\TestCase;

final class ConfigurationTest extends TestCase
{
    public function testDefaultsAndCustomBusinessPointDoNotRequireCommerceFramework(): void
    {
        self::assertSame(300, (new ProtectionPolicy())->passDuration);
        self::assertSame('production', (new ProtectionPolicy())->environment);
        self::assertSame('https://hideguard.io', (new ProtectionPolicy())->endpointUrl);
        self::assertSame('https://hideguard.io', ProtectionPolicy::defaultEndpointUrl());
        $policy = new ProtectionPolicy(
            enabled: true,
            publicKey: 'key',
            signaturePublicKey: 'signature',
            accessPoints: ['document.download']
        );
        self::assertTrue($policy->protects('document.download'));
        self::assertFalse($policy->protects('cart'));
        self::assertSame('user-uuid', (new AccessContext('tenant-uuid', 'browser', 'user-uuid'))->actorId);
        self::assertNull((new AccessContext('tenant', 'browser'))->actorId);
    }

    /** @dataProvider defaultOrigins */
    public function testCompatibleEnvironmentsUseTheLiveDefaultOrigin(string $environment, string $expected): void
    {
        self::assertSame($expected, ProtectionPolicy::defaultEndpointUrl($environment));
        self::assertSame($expected, (new ProtectionPolicy(environment: $environment))->endpointUrl);
        self::assertSame('https://custom.example', (new ProtectionPolicy(
            environment: $environment,
            endpointUrl: 'https://custom.example/'
        ))->endpointUrl);
    }

    public static function defaultOrigins(): array
    {
        return [
            ['development', 'https://hideguard.io'],
            ['production', 'https://hideguard.io'],
            ['staging', 'https://hideguard.io'],
        ];
    }

    public function testOnlyTwoModesAreOfferedAndUnknownDefaultEnvironmentFails(): void
    {
        self::assertSame(['development', 'production'], ProtectionPolicy::ENVIRONMENTS);
        $this->expectException(GuardException::class);
        ProtectionPolicy::defaultEndpointUrl('unknown');
    }

    /** @dataProvider endpointUrls */
    public function testHideGuardUrlIsNormalizedToAnHttpsOrigin(string $value, string $expected): void
    {
        self::assertSame($expected, (new ProtectionPolicy(endpointUrl: $value))->endpointUrl);
    }

    public static function endpointUrls(): array
    {
        return [
            ['https://hideguard.io', 'https://hideguard.io'],
            [' HTTPS://HIDEGUARD.EXAMPLE:443/ ', 'https://hideguard.example'],
            ['https://custom.hideguard.example:8443/', 'https://custom.hideguard.example:8443'],
            ['https://127.0.0.1:8443', 'https://127.0.0.1:8443'],
            ['https://[::1]:8443/', 'https://[::1]:8443'],
        ];
    }

    /** @dataProvider invalidEndpointUrls */
    public function testInvalidHideGuardUrlCannotBecomeAProtectionPolicy(string $value): void
    {
        $this->expectException(GuardException::class);
        $this->expectExceptionMessage('HideGuard URL must be an HTTPS origin');
        new ProtectionPolicy(endpointUrl: $value);
    }

    public static function invalidEndpointUrls(): array
    {
        return array_map(fn(string $value) => [$value], [
            '', 'http://hideguard.example', '//hideguard.example', 'https://', 'javascript:alert(1)',
            'https://user:pass@hideguard.example', 'https://@hideguard.example',
            'https://hideguard.example/sdk/v1.js', 'https://hideguard.example/.',
            'https://hideguard.example?key=value', 'https://hideguard.example?',
            'https://hideguard.example#fragment', 'https://hideguard.example#',
            'https://hideguard.example:65536', 'https://hideguard.example\\other',
            "https://hide\nguard.example", "https://hideguard.example\0", 'https://' . str_repeat('a', 2041),
        ]);
    }

    public function testChangingHideGuardOriginInvalidatesAPassButEquivalentOriginsDoNot(): void
    {
        $default = new ProtectionPolicy();
        self::assertSame(
            $default->fingerprint(),
            (new ProtectionPolicy(endpointUrl: 'HTTPS://HIDEGUARD.IO:443/'))->fingerprint()
        );
        self::assertNotSame(
            $default->fingerprint(),
            (new ProtectionPolicy(endpointUrl: 'https://another.hideguard.example'))->fingerprint()
        );
    }

    /** @dataProvider invalidPolicies */
    public function testInvalidConfigurationIsRejected(array $arguments): void
    {
        $this->expectException(GuardException::class);
        new ProtectionPolicy(...$arguments);
    }

    public static function invalidPolicies(): array
    {
        return [
            [['environment' => 'unknown']], [['passDuration' => -1]], [['passDuration' => 120]],
            [['blockDuration' => 0]], [['enabled' => true]],
            [['enabled' => true, 'environment' => 'production', 'publicKey' => 'key']],
            [['enabled' => true, 'publicKey' => 'key']],
            [['publicKey' => str_repeat('x', 1025)]], [['signaturePublicKey' => str_repeat('x', 4097)]],
            [['accessPoints' => ['bad/name']]], [['accessPoints' => [false]]],
            [['pageRules' => ["bad\0rule"]]], [['pageRules' => [str_repeat('x', 4097)]]],
            [['pageRules' => array_fill(0, 51, 'path')]],
        ];
    }

    /** @dataProvider invalidIdentities */
    public function testInvalidIdentityIsRejected(string $id): void
    {
        $this->expectException(GuardException::class);
        new AccessContext($id, 'browser');
    }

    public static function invalidIdentities(): array
    {
        return [[''], ["nul\0value"], [str_repeat('x', 129)]];
    }

    public function testDisabledDraftsAndPolicyFingerprintHaveStableSemantics(): void
    {
        $draft = new ProtectionPolicy(environment: 'production');
        self::assertFalse($draft->enabled);
        $one = new ProtectionPolicy(accessPoints: ['a', 'b'], pageRules: ['path/*', 'another']);
        $two = new ProtectionPolicy(accessPoints: ['b', 'a'], pageRules: ['another', 'path/*']);
        self::assertSame($one->fingerprint(), $two->fingerprint());
        self::assertNotSame($one->fingerprint(), (new ProtectionPolicy(passDuration: 60))->fingerprint());
    }

    public function testZeroLimitsAreRejected(): void
    {
        $this->expectException(GuardException::class);
        new RateLimits(identityRequests: 0);
    }

    public function testFactoryDoesNotFallBackToMemoryStorage(): void
    {
        try {
            Guard::factory()->make();
            self::fail('Storage must be supplied.');
        } catch (GuardException $error) {
            self::assertSame(FailureReason::InvalidConfiguration, $error->reason);
        }
    }

    public function testCustomStorageMustSupplyAtomicMutationOnItsOwnConnection(): void
    {
        $this->expectException(GuardException::class);
        $storage = $this->createMock(\Hachitechs\HideguardPhp\Contracts\StorageContract::class);
        Guard::factory()->withStorage($storage)->make();
    }

    public function testPdoDriverRejectsPersistentConnectionsBeforeUsingThem(): void
    {
        $pdo = $this->createMock(\PDO::class);
        $pdo->method('getAttribute')->willReturnMap([
            [\PDO::ATTR_DRIVER_NAME, 'mysql'], [\PDO::ATTR_PERSISTENT, true],
        ]);
        $pdo->expects(self::never())->method('prepare');
        $this->expectException(\InvalidArgumentException::class);
        new \Hachitechs\HideguardPhp\Storage\PdoMySqlStorage($pdo);
    }

    /** @dataProvider paths */
    public function testPathRulesPreserveLiteralCharactersAndCase(string $path, string $rule, bool $expected): void
    {
        self::assertSame($expected, (new PathMatcher())->matches($path, [$rule]));
    }

    public static function paths(): array
    {
        return [
            ['/docs/one?query=value', 'docs/*', true], ['/docs/one/two', 'docs/*', true],
            ['/a%2Bb', 'a+b', true], ['/A', 'a', false], ['/page[1]', 'page[1]', true],
            ['/page1', 'page[1]', false], ['/home', 'product/*', false],
            ['/contact?x=1', '/contact', true], ['/docs/a%0Ab', 'docs/*', true],
            ['/', '*', true], ['/', '', true], ['/anything', '', false],
            ['/abc', '**a**b**c**', true], ['/abc', 'a*c', true],
            ['/ab', 'ab*b', false], ['/ab', '*ab*b', false],
            ['/abcb', '*b*b', true], ['/abcb', 'a*c*d', false],
            ['/literal%3F%5C', 'literal?\\', true],
            ['/' . str_repeat('a', 30) . 'b', str_repeat('a*', 20) . 'b', true],
            ['/' . str_repeat('a', 30) . 'b', str_repeat('a*', 31) . 'b', false],
        ];
    }

    public function testProductionDependencyGraphAndSourceHaveNoFrameworkCoupling(): void
    {
        $root = dirname(__DIR__, 2);
        $manifest = json_decode(file_get_contents($root . '/composer.json'), true, 512, JSON_THROW_ON_ERROR);
        self::assertSame(['php', 'psr/clock', 'psr/log'], array_keys($manifest['require']));
        foreach (new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator($root . '/src')) as $file) {
            if ($file->getExtension() !== 'php') {
                continue;
            }
            $source = file_get_contents($file->getPathname());
            self::assertDoesNotMatchRegularExpression('/Magento\\\\|Illuminate\\\\|Symfony\\\\|\\bwp_/', $source);
            self::assertDoesNotMatchRegularExpression(
                '/\\$_(?:GET|POST|COOKIE|SESSION|SERVER)|\\b(?:header|session_start|exit)\\s*\\(/',
                $source
            );
        }
    }
}
