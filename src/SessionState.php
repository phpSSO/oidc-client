<?php

namespace JuliusPC\OpenIDConnect;

use JuliusPC\OpenIDConnect\Interfaces\StateStore;

/**
 * This StateStore implementation stores state, nonce, and code_verifier in a standard PHP session
 */
class SessionState implements StateStore
{
    public function __construct()
    {
        if (!isset($_SESSION)) {
            @session_start();
        }
    }

    public function getState(): string
    {
        return $_SESSION['oidc_state'];
    }

    public function getNonce(): string
    {
        return $_SESSION['oidc_nonce'];
    }

    public function getCodeVerifier(): string
    {
        return $_SESSION['oidc_code_verifier'];
    }

    public function setState(string $state): void
    {
        $_SESSION['oidc_state'] = $state;
    }

    public function setNonce(string $nonce): void
    {
        $_SESSION['oidc_nonce'] = $nonce;
    }

    public function setCodeVerifier(string $nonce): void
    {
        $_SESSION['oidc_code_verifier'] = $nonce;
    }

    public function unsetState(): void
    {
        unset($_SESSION['oidc_state']);
    }
    public function unsetNonce(): void
    {
        unset($_SESSION['oidc_nonce']);
    }
    public function unsetCodeVerifier(): void
    {
        unset($_SESSION['oidc_code_verifier']);
    }
}
