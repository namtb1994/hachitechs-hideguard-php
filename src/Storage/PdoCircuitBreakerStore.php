<?php

declare(strict_types=1);

namespace Hachitechs\HideguardPhp\Storage;

use Hachitechs\HideguardPhp\Access\CircuitPermit;
use Hachitechs\HideguardPhp\Configuration\CircuitBreakerPolicy;
use Hachitechs\HideguardPhp\Contracts\CircuitBreakerStoreContract;
use Hachitechs\HideguardPhp\Exceptions\ApiException;
use PDO;

final class PdoCircuitBreakerStore implements CircuitBreakerStoreContract
{
    private readonly string $table;
    public function __construct(private readonly PDO $pdo, string $table = 'hideguard_circuit')
    {
        $this->table = MySqlControl::identifier($table);
        if ($pdo->getAttribute(PDO::ATTR_DRIVER_NAME) !== 'mysql' || $pdo->getAttribute(PDO::ATTR_PERSISTENT)) {
            throw new \InvalidArgumentException('Use a dedicated non-persistent MySQL PDO connection.');
        }
        $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        $pdo->setAttribute(PDO::ATTR_EMULATE_PREPARES, false);
    }
    /** Explicit install/migration, never called by acquire/record. */
    public function initializeSchema(): void
    {
        if ($this->pdo->inTransaction()) {
            throw new \LogicException('Schema setup requires no transaction.');
        }
        $this->pdo->exec('CREATE TABLE IF NOT EXISTS ' . $this->table . ' ('
            . 'circuit_key CHAR(64) NOT NULL PRIMARY KEY, failures INT UNSIGNED NOT NULL DEFAULT 0, '
            . 'window_start BIGINT UNSIGNED NOT NULL DEFAULT 0, open_until BIGINT UNSIGNED NOT NULL DEFAULT 0, '
            . 'generation BIGINT UNSIGNED NOT NULL DEFAULT 0, probe_token CHAR(32) NULL, '
            . 'probe_until BIGINT UNSIGNED NOT NULL DEFAULT 0) ENGINE=InnoDB');
        $engine = $this->query('SELECT ENGINE FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE()'
            . ' AND TABLE_NAME=?', [trim($this->table, '`')])->fetchColumn();
        if ($engine !== 'InnoDB') {
            throw new \LogicException('Circuit state requires InnoDB transactions.');
        }
    }
    public function acquire(string $key, int $now, CircuitBreakerPolicy $policy): CircuitPermit
    {
        return $this->atomic($key, function (array $state) use ($now, $policy): array {
            if ((int)$state['open_until'] > $now) {
                throw new ApiException('HideGuard circuit is open.', 503);
            }
            if ((int)$state['open_until'] > 0) {
                if ($state['probe_token'] !== null && (int)$state['probe_until'] > $now) {
                    throw new ApiException('HideGuard recovery probe is already running.', 503);
                }
                $state['generation']++;
                $state['probe_token'] = bin2hex(random_bytes(16));
                $state['probe_until'] = $now + $policy->probeLeaseSeconds;
                return [$state, new CircuitPermit((int)$state['generation'], $state['probe_token'])];
            }
            if ((int)$state['window_start'] + $policy->windowSeconds <= $now) {
                $state['failures'] = 0;
                $state['window_start'] = $now;
                $state['generation']++;
            }
            return [$state, new CircuitPermit((int)$state['generation'])];
        });
    }
    public function record(
        string $key,
        CircuitPermit $permit,
        bool $failed,
        int $now,
        CircuitBreakerPolicy $policy
    ): void {
        $this->atomic($key, function (array $state) use ($permit, $failed, $now, $policy): array {
            if ((int)$state['generation'] !== $permit->generation) {
                return [$state, null];
            }
            if ($permit->probeToken !== null) {
                if ($state['probe_token'] !== $permit->probeToken || (int)$state['probe_until'] <= $now) {
                    return [$state, null];
                }
                $state['generation']++;
                $state['probe_token'] = null;
                $state['probe_until'] = 0;
                $state['open_until'] = $failed ? $now + $policy->openSeconds : 0;
                $state['failures'] = 0;
                $state['window_start'] = $now;
                return [$state, null];
            }
            if ((int)$state['open_until'] > 0) {
                return [$state, null];
            }
            if ((int)$state['window_start'] + $policy->windowSeconds <= $now) {
                $state['failures'] = 0;
                $state['window_start'] = $now;
            }
            $state['failures'] = $failed ? (int)$state['failures'] + 1 : 0;
            if (!$failed) {
                $state['window_start'] = $now;
            }
            if ((int)$state['failures'] >= $policy->threshold) {
                $state['open_until'] = $now + $policy->openSeconds;
                $state['generation']++;
            }
            return [$state, null];
        });
    }
    /** @param list<int|string|null> $args */
    private function query(string $sql, array $args): \PDOStatement
    {
        $statement = $this->pdo->prepare($sql);
        $statement->execute($args);
        return $statement;
    }
    private function rollbackIfActive(): void
    {
        if ($this->pdo->inTransaction()) {
            $this->pdo->rollBack();
        }
    }

    private function atomic(string $key, callable $work): mixed
    {
        if (!preg_match('/^[a-f0-9]{64}$/D', $key)) {
            throw new \InvalidArgumentException('Use a SHA-256 circuit key.');
        }
        if ($this->pdo->inTransaction()) {
            throw new \LogicException('Circuit state requires a dedicated connection.');
        }
        $previousWait = (int)$this->query('SELECT @@SESSION.innodb_lock_wait_timeout', [])->fetchColumn();
        $this->pdo->exec('SET SESSION innodb_lock_wait_timeout=1');
        try {
            $this->pdo->beginTransaction();
            $this->query('INSERT INTO ' . $this->table . ' (circuit_key) VALUES (?)'
                . ' ON DUPLICATE KEY UPDATE circuit_key=VALUES(circuit_key)', [$key]);
            $state = $this->query('SELECT * FROM ' . $this->table . ' WHERE circuit_key=? FOR UPDATE', [$key])
                ->fetch(PDO::FETCH_ASSOC);
            [$state, $result] = $work($state);
            $this->query('UPDATE ' . $this->table . ' SET failures=?, window_start=?, open_until=?, generation=?, '
                . 'probe_token=?, probe_until=? WHERE circuit_key=?', [$state['failures'], $state['window_start'],
                    $state['open_until'], $state['generation'], $state['probe_token'], $state['probe_until'], $key]);
            $this->pdo->commit();
            return $result;
        } catch (\Throwable $error) {
            $this->rollbackIfActive();
            throw $error;
        } finally {
            $this->pdo->exec('SET SESSION innodb_lock_wait_timeout=' . $previousWait);
        }
    }
}
