<?php

declare(strict_types=1);

/**
 *
 * Copyright MITRE 2020
 *
 * OpenIDConnectClient for PHP5
 * Author: Michael Jett <mjett@mitre.org>
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may
 * not use this file except in compliance with the License. You may obtain
 * a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 *
 * ------------------
 * 
 * This file was changed by Julius Cordes, 2020-2021.
 * For details see git history.
 * 
 */

namespace JuliusPC\OpenIDConnect;

use Exception;
use Jose\Easy\Load;
use GuzzleHttp\ClientInterface;
use JuliusPC\OpenIDConnect\Exceptions\{ClientException, ProviderException};
use JuliusPC\OpenIDConnect\Interfaces\StateStore;

class Client
{
    /**
     * @var Configuration holds the client's configuration
     */
    public Configuration $config;

    /**
     * @var ClientInterface HTTP client used to make Requests
     */
    private \GuzzleHttp\Client $httpClient;

    /**
     * @var StateStore holds the client's session state
     */
    private $state;

    /**
     * @var string if we acquire an access token it will be stored here
     */
    protected $accessToken;

    /**
     * @var string if we acquire a refresh token it will be stored here
     */
    private $refreshToken;

    /**
     * @var string if we acquire an id token it will be stored here
     */
    protected $idToken;

    /**
     * @var object stores the token response
     */
    private $tokenResponse;

    /**
     * @var int|null Response code from the server
     */
    private $responseCode;

    /**
     * @var object holds a cache of info returned from the userinfo endpoint
     */
    private $userInfo;

    /**
     * @var object holds verified jwt claims
     */
    protected object $verifiedClaims;

    /**
     * @var int defines which URL-encoding http_build_query() uses
     */
    protected int $encType = PHP_QUERY_RFC1738;

    /**
     * @var array holds PKCE supported algorithms
     */
    private $pkceAlgs = ['S256' => 'sha256', 'plain' => false];

    public function __construct(Configuration $configuration, ClientInterface $httpClient, StateStore $state)
    {
        $this->config = $configuration;
        $this->httpClient = $httpClient;
        $this->state = $state;
    }

    /**
     * @return bool
     * @throws ClientException
     */
    public function authenticate(array $authParams = []): bool
    {
        // protect against mix-up attacks
        // experimental feature, see https://tools.ietf.org/html/draft-ietf-oauth-iss-auth-resp-00
        if ((isset($_REQUEST['error']) || isset($_REQUEST['code']) || isset($_REQUEST['id_token']))
            && isset($_REQUEST['iss'])
            && $this->config->iss
            && !call_user_func($this->issuerValidator, $_REQUEST['iss'])
        ) {
            throw new ClientException('Error: validation of iss response parameter failed');
        }

        // Do a preemptive check to see if the provider has thrown an error from a previous redirect
        if (isset($_REQUEST['error'])) {
            $desc = isset($_REQUEST['error_description']) ? ' Description: ' . $_REQUEST['error_description'] : '';
            throw new ClientException('Error: ' . $_REQUEST['error'] . $desc);
        }

        // If we have an authorization code then proceed to request a token
        if (isset($_REQUEST['code'])) {

            $code = $_REQUEST['code'];
            $token_json = $this->requestTokens($code);

            // Throw an error if the server returns one
            if (isset($token_json->error)) {
                if (isset($token_json->error_description)) {
                    throw new ClientException($token_json->error_description);
                }
                throw new ClientException('Got response: ' . $token_json->error);
            }

            // Do a state check
            if ($this->state->getState() !== $_REQUEST['state']) {
                echo "{$this->state->getState()} !== {$_REQUEST['state']}";
                throw new ClientException('Unable to determine state');
            }

            // Cleanup state
            $this->state->unsetState();

            if (!property_exists($token_json, 'id_token')) {
                throw new ClientException('User did not authorize openid scope.');
            }

            // handle id_token and access_token
            if ($this->handleTokens($token_json->id_token, $token_json->access_token)) {
                // Save the full response
                $this->tokenResponse = $token_json;

                // Save the refresh token, if we got one
                if (isset($token_json->refresh_token)) {
                    $this->refreshToken = $token_json->refresh_token;
                }
            }

            return true;
        }

        if ($this->allowImplicitFlow && isset($_REQUEST['id_token'])) {
            // if we have no code but an id_token use that
            $id_token = $_REQUEST['id_token'];

            $accessToken = null;
            if (isset($_REQUEST['access_token'])) {
                $accessToken = $_REQUEST['access_token'];
            }

            // Do a state check
            if ($this->state->getState() !== $_REQUEST['state']) {
                throw new ClientException('Unable to determine state');
            }

            // Cleanup state
            $this->state->unsetState();

            return $this->handleTokens($id_token, $accessToken);
        }

        $this->requestAuthorization($authParams);
        return false;
    }

    /**
     * Verifies id_token und access_token and sets OIDC claims, read from verified id_token.
     *
     * @param string $idToken
     * @param string|null $accessToken
     * @return bool
     */
    protected function handleTokens(string $idToken, ?string $accessToken = null): bool
    {
        $jwt = Load::jws($idToken)
            ->keyset($this->config->getJwkSet())
            ->aud($this->config->client_id)
            ->algs($this->config->algs)
            ->exp($this->config->leeway)
            ->nbf($this->config->leeway)
            ->iat($this->config->leeway)
            ->iss($this->config->issuer)
            ->run();

        /*
        ToDo: Only validate if used / set:
            - at_hash
        */
        if (!isset($jwt)) {
            throw new ClientException('Unable to verify signature');
        }

        $claims = (array)$jwt->claims;

        if (isset($claims['nonce'])) {
            if ($claims['nonce'] !== $this->state->getNonce())
                throw new ClientException('Nonce does not match');
        }

        // Save the id token
        $this->idToken = $idToken;

        // Clean up the session a little
        $this->state->unsetNonce();

        // Save the verified claims
        $this->verifiedClaims = $claims;

        // Save the access token
        if ($accessToken) {
            $this->accessToken = $accessToken;
        }

        // Success!
        return true;
    }

    /**
     * It calls the end-session endpoint of the OpenID Connect provider to notify the OpenID
     * Connect provider that the end-user has logged out of the relying party site
     * (the client application).
     *
     * @param string|null $idToken ID token (obtained at login). In case this parameter is empty, it must be set with setIdToken().
     * @param string|null $postLogoutRedirectUri URL to which the RP is requesting that the End-User's User Agent
     * be redirected after a logout has been performed. The value MUST have been previously
     * registered with the OP. Value can be null.
     *
     * @throws ProviderException
     */
    public function signOut(?string $idToken, ?string $postLogoutRedirectUri): void
    {
        if ($idToken == null) {
            $idToken = $this->idToken;
        }
        $signout_endpoint = $this->config->getEndSessionEndpoint();

        $signout_params = null;
        if ($postLogoutRedirectUri === null) {
            $signout_params = ['id_token_hint' => $idToken];
        } else {
            $signout_params = [
                'id_token_hint' => $idToken,
                'post_logout_redirect_uri' => $postLogoutRedirectUri
            ];
        }

        $signout_endpoint  .= (strpos($signout_endpoint, '?') === false ? '?' : '&') . http_build_query($signout_params, '', '&', $this->encType);
        $this->redirect($signout_endpoint);
    }

    /**
     * Used for arbitrary value generation for nonces and state
     *
     * @param int $length Number of random bytes from which the string should be generated.
     * @return string hex encoded string (length of return is double of parameter $length)
     * @throws ClientException
     */
    protected function generateRandString(int $length = 16): string
    {
        try {
            return \bin2hex(\random_bytes($length));
        } catch (\Error $e) {
            throw new ClientException('Random token generation failed.');
        } catch (\Exception $e) {
            throw new ClientException('Random token generation failed.');
        };
    }

    /**
     * Start Here
     * @return void
     * @throws ClientException
     */
    private function requestAuthorization(array $authParams): void
    {

        $auth_endpoint = $this->config->getAuthorizationEndpoint();

        // State essentially acts as a session key for OIDC
        $state = $this->generateRandString();
        $this->state->setState($state);
        $response_types = $this->config->getResponseTypes();

        $auth_params = array_merge($authParams, [
            'response_type' => implode(' ', $response_types),
            'redirect_uri' => $this->config->getRedirectURI(),
            'client_id' => $this->config->client_id,
            'state' => $state,
            'scope' => implode(' ', array_merge($this->config->scopes))
        ]);

        // Generate and store a nonce in the session
        // The nonce is an arbitrary value
        if (!$this->unsafeDisableNonce) {
            $nonce = $this->generateRandString();
            $auth_params['nonce'] = $nonce;
            $this->state->setNonce($nonce);
        }

        // If the OP supports Proof Key for Code Exchange (PKCE) and it is enabled
        // PKCE will only used in pure authorization code flow and hybrid flow
        if (
            !$this->config->getUnsafeDisablePkce()
            && !empty($this->config->getCodeChallengeMethod())
            && (empty($response_types) || count(array_diff($response_types, ['token', 'id_token'])) > 0)
        ) {
            // 64 random bytes make up 128 characters encoded in hex.
            // RFC 7636 requires the code_verifier to be a random string with a minimum length of 43 characters
            // and a maximum length of 128 characters.
            // https://datatracker.ietf.org/doc/html/rfc7636#section-4.1
            $codeVerifier = $this->generateRandString(64);
            $this->state->setCodeVerifier($codeVerifier);
            if (!empty($this->pkceAlgs[$this->config->getCodeChallengeMethod()])) {
                $codeChallenge = rtrim(strtr(base64_encode(hash($this->pkceAlgs[$this->config->getCodeChallengeMethod()], $codeVerifier, true)), '+/', '-_'), '=');
            } else {
                $codeChallenge = $codeVerifier;
            }
            $auth_params = array_merge($auth_params, [
                'code_challenge' => $codeChallenge,
                'code_challenge_method' => $this->config->getCodeChallengeMethod()
            ]);
        }

        $auth_endpoint .= (strpos($auth_endpoint, '?') === false ? '?' : '&') . http_build_query($auth_params, '', '&', $this->encType);

        $this->redirect($auth_endpoint);
    }

    /**
     * Requests an access token with the client credentials grant. This grant is not covered by OpenID Connect.
     * 
     * @link https://tools.ietf.org/html/rfc6749#section-4.4
     *
     * @throws ClientException
     */
    public function requestClientCredentialsToken()
    {
        $token_endpoint = $this->config->getTokenEndpoint();
        $token_endpoint_auth_methods_supported = $this->config->getTokenEnpointAuthMethods();

        $headers = [];

        $grant_type = 'client_credentials';

        $post_data = [
            'grant_type'    => $grant_type,
            'client_id'     => $this->config->client_id,
            'client_secret' => $this->config->client_secret,
            'scope'         => implode(' ', $this->config->scopes)
        ];

        // Consider Basic authentication if provider config is set this way
        if (in_array('client_secret_basic', $token_endpoint_auth_methods_supported, true)) {
            $headers['Authorization'] = 'Basic ' . base64_encode(urlencode($this->config->client_id) . ':' . urlencode($this->config->client_secret));
            unset($post_data['client_secret']);
            unset($post_data['client_id']);
        }

        // Convert token params to string format
        $post_params = http_build_query($post_data, '', '&', $this->encType);

        return json_decode($this->fetchURL($token_endpoint, $post_params, $headers));
    }

    /**
     * Requests ID and Access Tokens
     *
     * @param string $code
     * @return mixed
     * @throws ClientException
     */
    protected function requestTokens($code)
    {
        $token_endpoint = $this->config->getTokenEndpoint();
        $token_endpoint_auth_methods_supported = $this->config->getTokenEnpointAuthMethods();

        $headers = [];

        $grant_type = 'authorization_code';

        $token_params = [
            'grant_type' => $grant_type,
            'code' => $code,
            'redirect_uri' => $this->config->getRedirectURI(),
            'client_id' => $this->config->client_id,
            'client_secret' => $this->config->client_secret
        ];

        // Consider Basic authentication if provider config is set this way
        if (in_array('client_secret_basic', $token_endpoint_auth_methods_supported, true)) {
            $headers['Authorization'] = 'Basic ' . base64_encode(urlencode($this->config->client_id) . ':' . urlencode($this->config->client_secret));
            unset($token_params['client_secret']);
            unset($token_params['client_id']);
        }

        if (
            !$this->unsafeDisablePkce
            && !empty($this->config->getCodeChallengeMethod())
        ) {
            $token_params = array_merge($token_params, [
                'code_verifier' => $this->state->getCodeVerifier()
            ]);
        }

        // Convert token params to string format
        $token_params = http_build_query($token_params, '', '&', $this->encType);

        $this->tokenResponse = json_decode($this->fetchURL($token_endpoint, $token_params, $headers));

        return $this->tokenResponse;
    }

    /**
     * Requests Access token with refresh token
     *
     * @param string $refresh_token
     * @param bool $sendScopes optional controls whether scopes are sent in the request, defaults to false
     * @return mixed
     * @throws ClientException
     */
    public function refreshToken($refresh_token, $sendScopes = false)
    {
        $token_endpoint = $this->config->getTokenEndpoint();
        $token_endpoint_auth_methods_supported = $this->config->getTokenEnpointAuthMethods();

        $headers = [];

        $grant_type = 'refresh_token';

        $token_params = [
            'grant_type' => $grant_type,
            'refresh_token' => $refresh_token,
            'client_id' => $this->config->client_id,
            'client_secret' => $this->config->client_secret,
        ];

        if ($sendScopes) {
            $token_params['scope'] = implode(' ', $this->config->scopes);
        }

        // Consider Basic authentication if provider config is set this way
        if (in_array('client_secret_basic', $token_endpoint_auth_methods_supported, true)) {
            $headers['Authorization'] = 'Basic ' . base64_encode(urlencode($this->config->client_id) . ':' . urlencode($this->config->client_secret));
            unset($token_params['client_secret']);
            unset($token_params['client_id']);
        }

        // Convert token params to string format
        $token_params = http_build_query($token_params, '', '&', $this->encType);

        $json = json_decode($this->fetchURL($token_endpoint, $token_params, $headers));

        if (isset($json->access_token)) {
            $this->accessToken = $json->access_token;
        }

        if (isset($json->refresh_token)) {
            $this->refreshToken = $json->refresh_token;
        }

        return $json;
    }

    /**
     * Calls the User Info endpoint to get a list of claims about the user.
     * List of standardized claims: https://openid.net/specs/openid-connect-core-1_0.html#StandardClaims
     *
     * @param string|null $claim optional: only return the specified claim
     *
     * @return mixed
     *
     * @throws ClientException
     */
    public function requestUserInfo(?string $claim = null)
    {
        if (empty($this->userInfo)) {
            $user_info_endpoint = $this->config->getUserinfoEndpoint();
            $headers = [];

            // The accessToken has to be sent in the Authorization header.
            // Accept json to indicate response type
            $headers['Authorization'] = 'Bearer ' . $this->accessToken;
            $headers['Accept'] = 'application/json';

            $user_json = json_decode($this->fetchURL($user_info_endpoint, null, $headers));
            if ($this->getResponseCode() <> 200) {
                throw new ClientException('The communication to retrieve user data has failed with status code ' . $this->getResponseCode());
            }

            /* ToDo: We need to verify that sub in response matches the one in the ID Token
             *       but we cannot rely on this beeing set because this function may be used  
             *       outside of an authentication flow...
             */
            $this->userInfo = $user_json;
        }

        if ($claim === null) {
            return $this->userInfo;
        }

        if (property_exists($this->userInfo, $claim)) {
            return $this->userInfo[$claim];
        }

        return null;
    }

    public function getIdTokenPayload()
    {
        // ToDo: implement
        throw new Exception('Not implemented yet!');
    }

    /**
     * @param string $url
     * @param string | null $post_body string If this is set the post type will be POST
     * @param array $headers Extra headers to be send with the request. Format as 'NameHeader: ValueHeader'
     * @throws ClientException
     * @return mixed
     */
    protected function fetchURL($url, $post_body = null, $headers = [])
    {
        $client = $this->httpClient;
        $method = 'GET';
        $options = [];

        // Determine whether this is a GET or POST
        if ($post_body !== null) {
            $method = 'POST';

            // Default content type is form encoded
            $content_type = 'application/x-www-form-urlencoded';

            // Determine if this is a JSON payload and add the appropriate content type
            if (is_object(json_decode($post_body))) {
                $content_type = 'application/json';
            }

            // Add POST-specific headers
            $headers['Content-Type'] = $content_type;

            $options['body'] = $post_body;
        }

        if (count($headers) > 0) {
            $options['headers'] = $headers;
        }

        $response = $client->request($method, $url, $options);

        // Download the given URL, and return output
        $output = $response->getBody()->getContents();

        // HTTP Response code from server may be required from subclass
        $this->responseCode = $response->getStatusCode();

        if ($this->responseCode != 200) {
            throw new ClientException('Error (Status Code ' . $this->responseCode . ') fetching resource ' . $url);
        }

        return $output;
    }

    /**
     * @param string $url
     */
    public function redirect($url): void
    {
        header('Location: ' . $url);
        exit;
    }

    /**
     * Introspect a given token - either access token or refresh token.
     * 
     * @link https://tools.ietf.org/html/rfc7662
     *
     * @param string $token
     * @param string $token_type_hint
     * @param string|null $clientId
     * @param string|null $clientSecret
     * @return mixed
     * @throws ClientException
     */
    public function introspectToken($token, $token_type_hint = '', $clientId = null, $clientSecret = null)
    {
        $introspection_endpoint = $this->config->getIntrospectionEndpoint();

        $post_data = ['token' => $token];

        if ($token_type_hint) {
            $post_data['token_type_hint'] = $token_type_hint;
        }
        $clientId = $clientId !== null ? $clientId : $this->config->client_id;
        $clientSecret = $clientSecret !== null ? $clientSecret : $this->config->client_secret;

        // Convert token params to string format
        $post_params = http_build_query($post_data, '', '&');
        $headers['Authorization'] = 'Basic ' . base64_encode(urlencode($clientId) . ':' . urlencode($clientSecret));
        $headers['Accept'] = 'application/json';

        return json_decode($this->fetchURL($introspection_endpoint, $post_params, $headers));
    }

    /**
     * Revoke a given token - either access token or refresh token.
     * @see https://tools.ietf.org/html/rfc7009
     *
     * @param string $token
     * @param string $token_type_hint
     * @param string|null $clientId
     * @param string|null $clientSecret
     * @return mixed
     * @throws ClientException
     */
    public function revokeToken($token, $token_type_hint = '', $clientId = null, $clientSecret = null)
    {
        $revocation_endpoint = $this->config->getRevocationEndpoint();

        $post_data = ['token' => $token];

        if ($token_type_hint) {
            $post_data['token_type_hint'] = $token_type_hint;
        }
        $clientId = $clientId !== null ? $clientId : $this->config->client_id;
        $clientSecret = $clientSecret !== null ? $clientSecret : $this->config->client_secret;

        // Convert token params to string format
        $post_params = http_build_query($post_data, '', '&');
        $headers['Authorization'] = 'Basic ' . base64_encode(urlencode($clientId) . ':' . urlencode($clientSecret));
        $headers['Accept'] = 'application/json';

        return json_decode($this->fetchURL($revocation_endpoint, $post_params, $headers));
    }

    /**
     * Request RFC8693 Token Exchange
     * https://datatracker.ietf.org/doc/html/rfc8693
     *
     * @param string $subjectToken
     * @param string $subjectTokenType
     * @param string $audience
     * @return mixed
     * @throws ClientException
     */
    public function requestTokenExchange($subjectToken, $subjectTokenType, $audience = '')
    {
        $token_endpoint = $this->config->getTokenEndpoint();
        $token_endpoint_auth_methods_supported = $this->config->getTokenEnpointAuthMethods();
        $headers = [];
        $grant_type = 'urn:ietf:params:oauth:grant-type:token-exchange';

        $post_data = array(
            'grant_type'    => $grant_type,
            'subject_token_type' => $subjectTokenType,
            'subject_token' => $subjectToken,
            'client_id' => $this->config->client_id,
            'client_secret' => $this->config->client_secret,
            'scope'         => implode(' ', $this->config->scopes)
        );

        if (!empty($audience)) {
            $post_data['audience'] = $audience;
        }

        # Consider Basic authentication if provider config is set this way
        if (in_array('client_secret_basic', $token_endpoint_auth_methods_supported, true)) {
            $headers['Authorization'] = 'Basic ' . base64_encode(urlencode($this->config->client_id) . ':' . urlencode($this->config->client_secret));
            unset($post_data['client_secret']);
            unset($post_data['client_id']);
        }

        // Convert token params to string format
        $post_params = http_build_query($post_data, '', '&', $this->encType);

        return json_decode($this->fetchURL($token_endpoint, $post_params, $headers));
    }

    /**
     * Set the access token.
     *
     * May be required for subclasses of this Client.
     *
     * @param string $accessToken
     * @return void
     */
    public function setAccessToken($accessToken)
    {
        $this->accessToken = $accessToken;
    }

    /**
     * @return string
     */
    public function getAccessToken(): string
    {
        return $this->accessToken;
    }

    /**
     * @return string
     */
    public function getRefreshToken(): ?string
    {
        return $this->refreshToken ?? null;
    }

    /**
     * @return string
     */
    public function getIdToken(): string
    {
        return $this->idToken;
    }

    /**
     * @param string $idToken
     */
    public function setIdToken(string $idToken): void
    {
        $this->idToken = $idToken;
        // needed to read verified claims from id_token
        $this->handleTokens($idToken);
    }

    /**
     * @return object
     */
    public function getTokenResponse(): object
    {
        return $this->tokenResponse;
    }

    /**
     * Get the response code from last HTTP request.
     *
     * @return int
     */
    public function getResponseCode(): int
    {
        return $this->responseCode;
    }

    public function setUrlEncoding($curEncoding)
    {
        switch ($curEncoding) {
            case PHP_QUERY_RFC1738:
                $this->encType = PHP_QUERY_RFC1738;
                break;

            case PHP_QUERY_RFC3986:
                $this->encType = PHP_QUERY_RFC3986;
                break;

            default:
                break;
        }
    }

    public function getConfiguration(): Configuration
    {
        return $this->config;
    }
}
