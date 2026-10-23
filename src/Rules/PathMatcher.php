<?php

declare(strict_types=1);

namespace Hachitechs\HideguardPhp\Rules;

final class PathMatcher
{
    public function normalize(string $path): string
    {
        return trim(rawurldecode(explode('?', $path, 2)[0]), '/');
    }

    /** @param list<string> $rules */
    public function matches(string $path, array $rules): bool
    {
        $path = $this->normalize($path);
        foreach ($rules as $rule) {
            if ($this->matchesRule($path, ltrim($rule, '/'))) {
                return true;
            }
        }
        return false;
    }

    private function matchesRule(string $path, string $rule): bool
    {
        $parts = explode('*', $rule);
        $last = count($parts) - 1;
        if ($last === 0) {
            return $path === $rule;
        }
        if (!str_starts_with($path, $parts[0]) || !str_ends_with($path, $parts[$last])) {
            return false;
        }

        // Locate literal chunks in order, without regex backtracking or fnmatch metacharacters.
        $offset = strlen($parts[0]);
        $suffixStart = strlen($path) - strlen($parts[$last]);
        for ($index = 1; $index < $last; $index++) {
            if ($parts[$index] === '') {
                continue;
            }
            $position = strpos($path, $parts[$index], $offset);
            if ($position === false) {
                return false;
            }
            $offset = $position + strlen($parts[$index]);
        }
        return $offset <= $suffixStart;
    }
}
