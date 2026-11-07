<?php

declare(strict_types=1);

namespace Hachitechs\HideguardPhp\Storage;

use Hachitechs\HideguardPhp\Access\BrowserState;
use Hachitechs\HideguardPhp\Access\RateWindow;
use Hachitechs\HideguardPhp\Access\ResourceRef;
use Hachitechs\HideguardPhp\Contracts\AtomicMutationContract;
use Hachitechs\HideguardPhp\Contracts\StorageContract;
use Hachitechs\HideguardPhp\Exceptions\FailureReason;
use Hachitechs\HideguardPhp\Exceptions\GuardException;
use Hachitechs\HideguardPhp\Contracts\PartitionedAtomicMutationContract;
use Hachitechs\HideguardPhp\Contracts\BatchCleanupContract;
use Hachitechs\HideguardPhp\Contracts\SessionCounterContract;
use Hachitechs\HideguardPhp\Access\CleanupResult;
use PDO;
use PDOStatement;

/** MySQL 8/InnoDB implementation. Supply a dedicated, non-persistent PDO connection. */
final class PdoMySqlStorage implements
    StorageContract,
    PartitionedAtomicMutationContract,
    BatchCleanupContract,
    SessionCounterContract
{
    private readonly MySqlControl $control;
    private readonly MySqlCoordinator $coordinator;

    public function __construct(
        private readonly PDO $pdo,
        private readonly string $prefix = 'hideguard_',
        int $lockWaitSeconds = 1
    ) {
        if (
            $pdo->getAttribute(PDO::ATTR_DRIVER_NAME) !== 'mysql'
            || $pdo->getAttribute(PDO::ATTR_PERSISTENT)
            || !preg_match('/^[a-zA-Z][a-zA-Z0-9_]{0,39}$/D', $prefix)
            || $lockWaitSeconds < 0 || $lockWaitSeconds > 10
        ) {
            throw new \InvalidArgumentException(
                'Use non-persistent MySQL, a safe table prefix and a lock wait of 0 to 10 seconds.'
            );
        }
        $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        $pdo->setAttribute(PDO::ATTR_EMULATE_PREPARES, false);
        $database = $this->execute('SELECT DATABASE()')->fetchColumn();
        if (!is_string($database) || $database === '') {
            throw new \InvalidArgumentException('Select a database in the PDO connection DSN.');
        }
        $this->control = new MySqlControl($pdo, $prefix . 'control', 'scope_id', $prefix . 'session');
        $this->coordinator = new MySqlCoordinator(
            $pdo,
            $this->control,
            fn(string $scope, string $browser) => $this->session($scope, $browser),
            $lockWaitSeconds
        );
    }

    /** Explicit setup only. Never run DDL inside an access mutation or an application request. */
    public function initializeSchema(): void
    {
        if ($this->pdo->inTransaction()) {
            throw new \LogicException('Schema initialization requires a connection outside any transaction.');
        }
        foreach ($this->schemaStatements() as $statement) {
            $this->pdo->exec($statement);
        }
        // Explicit, additive upgrade for installations created before verification attempts existed.
        $columns = $this->execute('SHOW COLUMNS FROM ' . $this->table('session'))->fetchAll(PDO::FETCH_COLUMN);
        $attemptColumns = [
            'verification_id' => 'CHAR(32) NULL',
            'verification_until' => 'BIGINT UNSIGNED NOT NULL DEFAULT 0',
        ];
        foreach ($attemptColumns as $column => $definition) {
            if (!in_array($column, $columns, true)) {
                $this->pdo->exec('ALTER TABLE ' . $this->table('session') . ' ADD ' . $column . ' ' . $definition);
            }
        }
        $engines = $this->execute(
            'SELECT ENGINE FROM information_schema.TABLES WHERE TABLE_SCHEMA = DATABASE() '
            . 'AND TABLE_NAME IN (?, ?, ?, ?)',
            [$this->prefix . 'session', $this->prefix . 'block', $this->prefix . 'rate', $this->prefix . 'control']
        )->fetchAll(PDO::FETCH_COLUMN);
        if (count($engines) !== 4 || array_diff($engines, ['InnoDB']) !== []) {
            throw new \LogicException('All access storage tables must use InnoDB transactions.');
        }
        $scopes = $this->execute('SELECT DISTINCT scope_id FROM ' . $this->table('session'))
            ->fetchAll(PDO::FETCH_COLUMN);
        foreach ($scopes as $scope) {
            $this->run((string)$scope, fn() => $this->reconcileSessionCount((string)$scope));
        }
    }

    public function run(string $scopeId, callable $work): mixed
    {
        return $this->coordinator->run($scopeId, $work);
    }

    public function runBrowser(string $scopeId, string $browserId, ?ResourceRef $resource, callable $work): mixed
    {
        return $this->coordinator->runBrowser($scopeId, $browserId, $resource, $work);
    }

    public function runResource(string $scopeId, ResourceRef $resource, callable $work): mixed
    {
        return $this->coordinator->runResource($scopeId, $resource, $work);
    }

    public function reconcileSessionCount(string $scopeId): int
    {
        return $this->control->reconcile($scopeId);
    }

    public function session(string $scopeId, string $browserId): ?BrowserState
    {
        return $this->fetchState(
            'SELECT * FROM ' . $this->table('session') . ' WHERE scope_id = ? AND browser_id = ?',
            [$scopeId, $browserId]
        );
    }

    public function saveSession(string $scopeId, BrowserState $state): void
    {
        $new = $this->control->beforeSave($scopeId, $state->browserId, 'browser_id');
        $this->execute(
            'INSERT INTO ' . $this->table('session') . ' (scope_id, browser_id, actor_id, visitor_id, blocked_until, '
            . 'granted_until, policy_hash, resource_type, resource_id, last_seen, verification, '
            . 'verification_id, verification_until) '
            . 'VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON DUPLICATE KEY UPDATE '
            . 'actor_id = VALUES(actor_id), visitor_id = VALUES(visitor_id), blocked_until = VALUES(blocked_until), '
            . 'granted_until = VALUES(granted_until), policy_hash = VALUES(policy_hash), '
            . 'resource_type = VALUES(resource_type), resource_id = VALUES(resource_id), '
            . 'last_seen = VALUES(last_seen), verification = VALUES(verification), '
            . 'verification_id = VALUES(verification_id), verification_until = VALUES(verification_until)',
            [
                $scopeId, $state->browserId, $state->actorId, $state->visitorId, $state->blockedUntil,
                $state->grantedUntil, $state->policyHash, $state->resource?->type, $state->resource?->id,
                $state->lastSeen, $state->verification, $state->verificationId, $state->verificationUntil,
            ]
        );
        if ($new) {
            $this->control->inserted($scopeId);
        }
    }

    public function sessionCount(string $scopeId): int
    {
        return $this->control->count($scopeId);
    }

    public function blockExpiry(string $scopeId, ?string $visitorId, ?string $actorId): int
    {
        $hashes = $this->identityHashes($visitorId, $actorId);
        if ($hashes === []) {
            return 0;
        }
        return (int)$this->execute(
            'SELECT MAX(blocked_until) FROM ' . $this->table('block') . ' WHERE scope_id = ? AND identity_hash IN ('
            . implode(', ', array_fill(0, count($hashes), '?')) . ')',
            array_merge([$scopeId], $hashes)
        )->fetchColumn();
    }

    public function block(string $scopeId, string $visitorId, ?string $actorId, int $until): void
    {
        foreach ($this->identityHashes($visitorId, $actorId) as $hash) {
            $this->execute(
                'INSERT INTO ' . $this->table('block') . ' (scope_id, identity_hash, blocked_until) VALUES (?, ?, ?) '
                . 'ON DUPLICATE KEY UPDATE blocked_until = VALUES(blocked_until)',
                [$scopeId, $hash, $until]
            );
        }
    }

    public function revokeIdentity(string $scopeId, ?string $visitorId, ?string $actorId): void
    {
        $conditions = [];
        $params = [$scopeId];
        if ($visitorId !== null) {
            $conditions[] = 'visitor_id = ?';
            $params[] = $visitorId;
        }
        if ($actorId !== null) {
            $conditions[] = 'actor_id = ?';
            $params[] = $actorId;
        }
        if ($conditions !== []) {
            $this->revoke('scope_id = ? AND (' . implode(' OR ', $conditions) . ')', $params);
        }
    }

    public function bindResource(string $scopeId, string $browserId, ResourceRef $resource): void
    {
        $this->execute(
            'UPDATE ' . $this->table('session') . ' SET resource_type = NULL, resource_id = NULL '
            . 'WHERE scope_id = ? AND resource_type = ? AND resource_id = ? AND browser_id <> ?',
            [$scopeId, $resource->type, $resource->id, $browserId]
        );
        $this->execute(
            'UPDATE ' . $this->table('session') . ' SET resource_type = ?, resource_id = ? '
            . 'WHERE scope_id = ? AND browser_id = ?',
            [$resource->type, $resource->id, $scopeId, $browserId]
        );
    }

    public function resource(string $scopeId, ResourceRef $resource): ?BrowserState
    {
        return $this->fetchState(
            'SELECT * FROM ' . $this->table('session')
            . ' WHERE scope_id = ? AND resource_type = ? AND resource_id = ?',
            [$scopeId, $resource->type, $resource->id]
        );
    }

    public function revokeResource(string $scopeId, ResourceRef $resource): void
    {
        $this->revoke(
            'scope_id = ? AND resource_type = ? AND resource_id = ?',
            [$scopeId, $resource->type, $resource->id]
        );
    }

    public function revokeScope(string $scopeId): void
    {
        $this->revoke('scope_id = ?', [$scopeId]);
    }

    public function resetBlocks(string $scopeId): int
    {
        $count = $this->execute('DELETE FROM ' . $this->table('block') . ' WHERE scope_id = ?', [$scopeId])->rowCount();
        $this->execute('UPDATE ' . $this->table('session') . ' SET blocked_until = 0 WHERE scope_id = ?', [$scopeId]);
        return $count;
    }

    public function rate(string $scopeId, string $bucketHash): ?RateWindow
    {
        if ($this->pdo->inTransaction() && $bucketHash === hash('sha256', 'scope')) {
            $row = $this->control->lockScopeRate($this->prefix . 'rate', $scopeId, $bucketHash);
            return $row === null ? null : new RateWindow((int)$row['requests'], (int)$row['expires_at']);
        }
        $row = $this->execute(
            'SELECT requests, expires_at FROM ' . $this->table('rate') . ' WHERE scope_id = ? AND bucket_hash = ?',
            [$scopeId, $bucketHash]
        )->fetch(PDO::FETCH_ASSOC);
        return is_array($row) ? new RateWindow((int)$row['requests'], (int)$row['expires_at']) : null;
    }

    public function saveRate(string $scopeId, string $bucketHash, RateWindow $window): void
    {
        $this->execute(
            'INSERT INTO ' . $this->table('rate')
            . ' (scope_id, bucket_hash, requests, expires_at) VALUES (?, ?, ?, ?) '
            . 'ON DUPLICATE KEY UPDATE requests = VALUES(requests), expires_at = VALUES(expires_at)',
            [$scopeId, $bucketHash, $window->requests, $window->expiresAt]
        );
    }

    public function cleanup(string $scopeId, int $now, int $inactiveBefore): void
    {
        while ($this->cleanupBatch($scopeId, $now, $inactiveBefore, 500)->hasMore) {
        }
    }

    public function cleanupBatch(string $scopeId, int $now, int $inactiveBefore, int $limit): CleanupResult
    {
        if ($limit < 1 || $limit > 10000) {
            throw new \InvalidArgumentException('Batch limit must be between 1 and 10000.');
        }
        $counts = [];
        $conditions = [
            'block' => ['blocked_until<=?', [$now]],
            'rate' => ['expires_at<=?', [$now]],
            'session' => ['last_seen<? AND blocked_until<=? AND granted_until<=? AND verification_until<=?',
                [$inactiveBefore, $now, $now, $now]],
        ];
        $remaining = $limit;
        foreach ($conditions as $suffix => [$where, $params]) {
            $counts[$suffix] = 0;
            if ($remaining === 0) {
                continue;
            }
            if ($suffix === 'session') {
                $this->control->count($scopeId);
            }
            $counts[$suffix] = $this->execute(
                'DELETE FROM ' . $this->table($suffix)
                . ' WHERE scope_id=? AND ' . $where . ' LIMIT ' . $remaining,
                array_merge([$scopeId], $params)
            )->rowCount();
            if ($suffix === 'session') {
                $this->control->removed($scopeId, $counts[$suffix]);
            }
            $remaining -= $counts[$suffix];
        }
        return new CleanupResult($counts['block'], $counts['rate'], $counts['session'], $remaining === 0);
    }

    /** @param list<int|string|null> $params */
    private function execute(string $sql, array $params = []): PDOStatement
    {
        $statement = $this->pdo->prepare($sql);
        $statement->execute($params);
        return $statement;
    }

    /** @param list<int|string|null> $params */
    private function fetchState(string $sql, array $params): ?BrowserState
    {
        $row = $this->execute($sql, $params)->fetch(PDO::FETCH_ASSOC);
        if (!is_array($row)) {
            return null;
        }
        $actor = $row['actor_id'] !== null ? (string)$row['actor_id'] : null;
        return new BrowserState(
            (string)$row['browser_id'],
            $actor,
            $row['visitor_id'] !== null ? (string)$row['visitor_id'] : null,
            (int)$row['blocked_until'],
            (int)$row['granted_until'],
            $row['policy_hash'] !== null ? (string)$row['policy_hash'] : null,
            $row['resource_type'] !== null && $row['resource_id'] !== null
                ? new ResourceRef((string)$row['resource_type'], (string)$row['resource_id'], $actor) : null,
            (int)$row['last_seen'],
            (string)$row['verification'],
            $row['verification_id'] !== null ? (string)$row['verification_id'] : null,
            (int)$row['verification_until']
        );
    }

    /** @param list<int|string|null> $params */
    private function revoke(string $condition, array $params): void
    {
        $this->execute(
            'UPDATE ' . $this->table('session')
            . ' SET granted_until = 0, resource_type = NULL, resource_id = NULL, '
            . 'verification_id = NULL, verification_until = 0 WHERE '
            . $condition,
            $params
        );
    }

    /** @return list<string> */
    private function identityHashes(?string $visitorId, ?string $actorId): array
    {
        $hashes = [];
        if ($visitorId !== null) {
            $hashes[] = hash('sha256', 'visitor:' . $visitorId);
        }
        if ($actorId !== null) {
            $hashes[] = hash('sha256', 'actor:' . $actorId);
        }
        return $hashes;
    }

    private function table(string $suffix): string
    {
        return '`' . $this->prefix . $suffix . '`';
    }

    /** @return list<string> */
    private function schemaStatements(): array
    {
        return [
            'CREATE TABLE IF NOT EXISTS ' . $this->table('control') . ' ('
            . 'scope_id VARBINARY(128) NOT NULL, name VARBINARY(32) NOT NULL, '
            . 'value BIGINT UNSIGNED NOT NULL DEFAULT 0, initialized SMALLINT UNSIGNED NOT NULL DEFAULT 0, '
            . 'PRIMARY KEY (scope_id, name)) ENGINE=InnoDB',
            'CREATE TABLE IF NOT EXISTS ' . $this->table('session') . ' ('
            . 'scope_id VARBINARY(128) NOT NULL, browser_id VARBINARY(128) NOT NULL, '
            . 'actor_id VARBINARY(128) NULL, visitor_id VARBINARY(128) NULL, '
            . 'blocked_until BIGINT UNSIGNED NOT NULL DEFAULT 0, granted_until BIGINT UNSIGNED NOT NULL DEFAULT 0, '
            . 'policy_hash CHAR(64) NULL, resource_type VARBINARY(128) NULL, resource_id VARBINARY(128) NULL, '
            . 'last_seen BIGINT UNSIGNED NOT NULL, verification VARCHAR(32) NOT NULL DEFAULT \'\', '
            . 'verification_id CHAR(32) NULL, verification_until BIGINT UNSIGNED NOT NULL DEFAULT 0, '
            . 'PRIMARY KEY (scope_id, browser_id), UNIQUE KEY resource_binding (scope_id, resource_type, resource_id), '
            . 'KEY visitor_lookup (scope_id, visitor_id), KEY actor_lookup (scope_id, actor_id), '
            . 'KEY activity (last_seen)'
            . ') ENGINE=InnoDB',
            'CREATE TABLE IF NOT EXISTS ' . $this->table('block') . ' ('
            . 'scope_id VARBINARY(128) NOT NULL, identity_hash CHAR(64) NOT NULL, '
            . 'blocked_until BIGINT UNSIGNED NOT NULL, '
            . 'PRIMARY KEY (scope_id, identity_hash), KEY expiry (blocked_until)) ENGINE=InnoDB',
            'CREATE TABLE IF NOT EXISTS ' . $this->table('rate') . ' ('
            . 'scope_id VARBINARY(128) NOT NULL, bucket_hash CHAR(64) NOT NULL, requests BIGINT UNSIGNED NOT NULL, '
            . 'expires_at BIGINT UNSIGNED NOT NULL, PRIMARY KEY (scope_id, bucket_hash), KEY expiry (expires_at)'
            . ') ENGINE=InnoDB',
        ];
    }
}
