<?php

declare(strict_types=1);

namespace Hachitech\Antidetect;

use Hachitech\Antidetect\Contracts\AtomicMutationContract;
use Hachitech\Antidetect\Contracts\StorageContract;
use Hachitech\Antidetect\Contracts\VerdictVerifier;
use Hachitech\Antidetect\Exceptions\FailureReason;
use Hachitech\Antidetect\Exceptions\GuardException;
use Hachitech\Antidetect\Support\SystemClock;
use Hachitech\Antidetect\Verification\UnavailableVerifier;
use Psr\Clock\ClockInterface;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;

final class Factory
{
    private ?StorageContract $storage = null;
    private ?AtomicMutationContract $atomic = null;
    private ?VerdictVerifier $verifier = null;
    private ?ClockInterface $clock = null;
    private ?LoggerInterface $logger = null;

    public function withStorage(StorageContract $storage): self
    {
        $this->storage = $storage;
        return $this;
    }

    public function withAtomicMutation(AtomicMutationContract $atomic): self
    {
        $this->atomic = $atomic;
        return $this;
    }

    public function withVerifier(VerdictVerifier $verifier): self
    {
        $this->verifier = $verifier;
        return $this;
    }

    public function withClock(ClockInterface $clock): self
    {
        $this->clock = $clock;
        return $this;
    }

    public function withLogger(LoggerInterface $logger): self
    {
        $this->logger = $logger;
        return $this;
    }

    public function make(): Guard
    {
        $atomic = $this->atomic ?? ($this->storage instanceof AtomicMutationContract ? $this->storage : null);
        if ($this->storage === null || $atomic === null) {
            throw new GuardException(
                FailureReason::InvalidConfiguration,
                'Persistent storage and its atomic mutation implementation are required.'
            );
        }
        return new Guard(
            $this->storage,
            $atomic,
            $this->verifier ?? new UnavailableVerifier(),
            $this->clock ?? new SystemClock(),
            $this->logger ?? new NullLogger()
        );
    }
}
