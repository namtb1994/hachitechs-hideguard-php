<?php

declare(strict_types=1);

namespace Hachitechs\HideguardPhp\Tests\Unit;

use Hachitechs\HideguardPhp\Storage\MySqlControl;
use Hachitechs\HideguardPhp\Storage\MySqlCoordinator;
use PHPUnit\Framework\TestCase;

final class MySqlCoordinatorTest extends TestCase
{
    /** @dataProvider invalidWaits */
    public function testUnboundedWaitIsRejectedBeforeDatabaseWork(int $wait): void
    {
        $control = $this->createMock(MySqlControl::class);
        $control->expects(self::never())->method('query');
        $this->expectException(\InvalidArgumentException::class);
        new MySqlCoordinator($this->createStub(\PDO::class), $control, fn() => null, $wait);
    }

    public static function invalidWaits(): array
    {
        return [[-1], [11]];
    }
}
