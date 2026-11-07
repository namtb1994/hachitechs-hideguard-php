<?php

declare(strict_types=1);

namespace Hachitechs\HideguardPhp\Storage;

use Hachitechs\HideguardPhp\Access\ResourceRef;
use Hachitechs\HideguardPhp\Contracts\PartitionedAtomicMutationContract;
use Hachitechs\HideguardPhp\Exceptions\{GuardException, FailureReason};
use PDO;

/** Browser/resource mutexes plus a shared/exclusive scope fence. Reports remain exclusive. */
final class MySqlCoordinator implements PartitionedAtomicMutationContract
{
    private readonly \Closure $snapshot;
    private readonly string $namespace;
    public function __construct(
        private readonly PDO $pdo,
        private readonly MySqlControl $control,
        callable $snapshot,
        private readonly int $waitSeconds = 1
    ) {
        if ($waitSeconds < 0 || $waitSeconds > 10) {
            throw new \InvalidArgumentException('Lock wait must be between 0 and 10 seconds.');
        }
        $this->snapshot = \Closure::fromCallable($snapshot);
        $this->namespace = (string)$control->query('SELECT DATABASE()')->fetchColumn() . ':' . $control->table();
    }
    public function run(string $scopeId, callable $work): mixed
    {
        return $this->execute($scopeId, null, null, true, $work);
    }
    public function runBrowser(string $scopeId, string $browserId, ?ResourceRef $resource, callable $work): mixed
    {
        return $this->execute($scopeId, $browserId, $resource, false, $work);
    }
    public function runResource(string $scopeId, ResourceRef $resource, callable $work): mixed
    {
        return $this->execute($scopeId, null, $resource, false, $work);
    }
    private function execute(
        string $scope,
        ?string $browser,
        ?ResourceRef $resource,
        bool $exclusive,
        callable $work
    ): mixed {
        if ($this->pdo->inTransaction()) {
            throw new \LogicException('Nested/external transactions are unsupported.');
        }
        $locks = [];
        $previousWait = (int)$this->control->query('SELECT @@SESSION.innodb_lock_wait_timeout')->fetchColumn();
        $this->pdo->exec('SET SESSION innodb_lock_wait_timeout=' . max(1, $this->waitSeconds));
        try {
            if ($browser !== null) {
                $this->lock($scope, 'browser:' . $browser, $locks);
            }
            $this->control->ensureFence($scope);
            $this->pdo->exec('SET TRANSACTION ISOLATION LEVEL READ COMMITTED');
            $this->pdo->beginTransaction();
            $this->control->fence($scope, $exclusive, $this->waitSeconds === 0);
            $resources = [];
            if ($resource !== null) {
                $resources[] = $resource;
            }
            if ($browser !== null) {
                $state = ($this->snapshot)($scope, $browser);
                if ($state?->resource !== null) {
                    $resources[] = $state->resource;
                }
            }
            $keys = [];
            foreach ($resources as $item) {
                $keys[] = 'resource:' . strlen($item->type) . ':' . $item->type . $item->id;
            }
            sort($keys, SORT_STRING);
            foreach (array_unique($keys) as $key) {
                $this->lock($scope, $key, $locks);
            }
            try {
                try {
                    $result = $work();
                } catch (GuardException $error) {
                    $this->pdo->commit();
                    throw $error;
                }
                $this->pdo->commit();
                return $result;
            } catch (\Throwable $error) {
                if ($this->pdo->inTransaction()) {
                    $this->pdo->rollBack();
                }
                throw $error;
            }
        } catch (\PDOException $error) {
            if (in_array((int)($error->errorInfo[1] ?? 0), [1205, 1213, 3572], true)) {
                throw new GuardException(FailureReason::Busy, 'Access storage is busy. Retry shortly.', 1);
            }
            throw $error;
        } finally {
            if ($this->pdo->inTransaction()) {
                $this->pdo->rollBack();
            }
            foreach (array_reverse($locks) as $name) {
                $this->control->query('SELECT RELEASE_LOCK(?)', [$name]);
            }
            $this->pdo->exec('SET SESSION innodb_lock_wait_timeout=' . $previousWait);
        }
    }
    /** @param list<string> $locks */
    private function lock(string $scope, string $key, array &$locks): void
    {
        $name = hash('sha256', $this->namespace . ':' . strlen($scope) . ':' . $scope . ':' . $key);
        if ((int)$this->control->query('SELECT GET_LOCK(?,?)', [$name, $this->waitSeconds])->fetchColumn() !== 1) {
            throw new GuardException(FailureReason::Busy, 'Access storage is busy. Retry shortly.', 1);
        }
        $locks[] = $name;
    }
}
