<?php

declare(strict_types=1);

namespace Hachitechs\HideguardPhp\Exceptions;

/** Infrastructure failure; deliberately separate from intentional Guard rejections. */
final class ApiException extends \RuntimeException
{
    public function __construct(
        string $message,
        public readonly ?int $statusCode = null,
        ?\Throwable $previous = null
    ) {
        parent::__construct($message, $statusCode ?? 0, $previous);
    }
}
