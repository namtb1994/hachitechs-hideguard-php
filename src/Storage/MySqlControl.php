<?php

declare(strict_types=1);

namespace Hachitechs\HideguardPhp\Storage;

use PDO;

/** Shared implementation for standalone PDO and framework adapters; no framework dependency. */
class MySqlControl
{
    public function __construct(
        private readonly PDO $pdo,
        private readonly string $table,
        private readonly string $scopeColumn,
        private readonly string $sessionTable
    ) {
        foreach ([$table, $scopeColumn, $sessionTable] as $name) {
            self::identifier($name);
        }
    }
    public static function identifier(string $name): string
    {
        if (!preg_match('/^[A-Za-z0-9_]{1,128}$/D', $name)) {
            throw new \InvalidArgumentException('Unsafe SQL identifier.');
        }
        return '`' . $name . '`';
    }
    /** @param list<int|string|null> $params */
    public function query(string $sql, array $params = []): \PDOStatement
    {
        $statement = $this->pdo->prepare($sql);
        $statement->execute($params);
        return $statement;
    }
    public function table(): string
    {
        return self::identifier($this->table);
    }
    public function scope(): string
    {
        return self::identifier($this->scopeColumn);
    }
    public function ensureFence(string $scope): void
    {
        $this->query('INSERT IGNORE INTO ' . $this->table() . ' (' . $this->scope()
            . ', name, value, initialized) VALUES (?, ?, 0, 1)', [$scope, 'fence']);
    }
    public function fence(string $scope, bool $exclusive, bool $nowait = false): void
    {
        $this->query(
            'SELECT value FROM ' . $this->table() . ' WHERE ' . $this->scope()
            . '=? AND name=? ' . ($exclusive ? 'FOR UPDATE' : 'FOR SHARE') . ($nowait ? ' NOWAIT' : ''),
            [$scope, 'fence']
        )->fetchColumn();
    }
    public function count(string $scope): int
    {
        $own = !$this->pdo->inTransaction();
        if ($own) {
            $this->pdo->beginTransaction();
        }
        try {
            $this->query('INSERT INTO ' . $this->table() . ' (' . $this->scope()
                . ', name, value, initialized) VALUES (?, ?, 0, 0)'
                . ' ON DUPLICATE KEY UPDATE name=VALUES(name)', [$scope, 'sessions']);
            $row = $this->query('SELECT value, initialized FROM ' . $this->table() . ' WHERE '
                . $this->scope() . '=? AND name=? FOR UPDATE', [$scope, 'sessions'])->fetch(PDO::FETCH_ASSOC);
            $value = (int)$row['value'];
            if (!(int)$row['initialized']) {
                $value = $this->reconcile($scope);
            }
            if ($own) {
                $this->pdo->commit();
            }
            return $value;
        } catch (\Throwable $error) {
            if ($own && $this->pdo->inTransaction()) {
                $this->pdo->rollBack();
            }
            throw $error;
        }
    }
    public function reconcile(string $scope): int
    {
        $this->requireTransaction();
        $value = (int)$this->query('SELECT COUNT(*) FROM ' . self::identifier($this->sessionTable)
            . ' WHERE ' . $this->scope() . '=?', [$scope])->fetchColumn();
        $this->query(
            'INSERT INTO ' . $this->table() . ' (' . $this->scope()
            . ', name, value, initialized) VALUES (?, ?, ?, 1)'
            . ' ON DUPLICATE KEY UPDATE value=VALUES(value), initialized=1',
            [$scope, 'sessions', $value]
        );
        return $value;
    }
    public function beforeSave(string $scope, string $browser, string $browserColumn): bool
    {
        $this->requireTransaction();
        $exists = $this->query('SELECT 1 FROM ' . self::identifier($this->sessionTable) . ' WHERE '
            . $this->scope() . '=? AND ' . self::identifier($browserColumn) . '=?', [$scope, $browser])->fetchColumn();
        if ($exists !== false) {
            return false;
        }
        $this->count($scope);
        return true;
    }
    public function inserted(string $scope): void
    {
        $this->requireTransaction();
        $this->query('UPDATE ' . $this->table() . ' SET value=value+1 WHERE ' . $this->scope()
            . '=? AND name=?', [$scope, 'sessions']);
    }
    public function removed(string $scope, int $count): void
    {
        $this->requireTransaction();
        $statement = $this->query('UPDATE ' . $this->table() . ' SET value=value-? WHERE '
            . $this->scope() . '=? AND name=? AND value>=?', [$count, $scope, 'sessions', $count]);
        if ($count > 0 && $statement->rowCount() !== 1) {
            throw new \LogicException('Session counter drift; reconcile explicitly.');
        }
    }
    /** @return array<string, mixed>|null */
    public function lockScopeRate(string $table, string $scope, string $hash): ?array
    {
        $this->requireTransaction();
        $sql = 'SELECT requests, expires_at FROM ' . self::identifier($table) . ' WHERE '
            . $this->scope() . '=? AND bucket_hash=? FOR UPDATE';
        $row = $this->query($sql, [$scope, $hash])->fetch(PDO::FETCH_ASSOC);
        if ($row === false) {
            $this->query('INSERT INTO ' . self::identifier($table) . ' (' . $this->scope()
                . ',bucket_hash,requests,expires_at) VALUES (?,?,0,0)'
                . ' ON DUPLICATE KEY UPDATE bucket_hash=VALUES(bucket_hash)', [$scope, $hash]);
            $row = $this->query($sql, [$scope, $hash])->fetch(PDO::FETCH_ASSOC);
        }
        return (int)$row['expires_at'] === 0 ? null : $row;
    }
    private function requireTransaction(): void
    {
        if (!$this->pdo->inTransaction()) {
            throw new \LogicException('Storage mutation requires an atomic transaction.');
        }
    }
}
