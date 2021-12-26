<?php

declare(strict_types=1);

namespace JuliusPC\OpenIDConnect\Interfaces;

interface StateStore
{
    public function getState(): string;
    public function getNonce(): string;
    public function getCodeVerifier(): string;

    public function setState(string $state): void;
    public function setNonce(string $nonce): void;
    public function setCodeVerifier(string $nonce): void;

    public function unsetState(): void;
    public function unsetNonce(): void;
    public function unsetCodeVerifier(): void;
}
