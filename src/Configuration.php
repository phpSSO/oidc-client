<?php

declare(strict_types=1);

namespace JuliusPC\OpenIDConnect;

use Jose\Component\Core\JWK;
use Jose\Component\Core\JWKSet;
use Jose\Component\KeyManagement\JWKFactory;
use JuliusPC\OpenIDConnect\Exceptions\ProviderException;
use JuliusPC\OpenIDConnect\Interfaces\State;
use JuliusPC\OpenIDConnect\SessionState;

class Configuration
{
    public string $client_id;
    public ?string $client_secret;
    private ?string $redirect_uri;
    public string $issuer;
    private array $wellKnownConfig;

    private ?string $codeChallengeMethod = null;

    public int $leeway = 300;

    public array $jwks = [];

    // ToDo: discover algs in discovery document
    public array $algs = ['RS256', 'RS384', 'RS512', 'HS256', 'HS384', 'HS512'];

    /**
     * @var array<string>
     */
    public array $scopes = ['openid'];

    /**
     * @var array<string>
     */
    public array $response_types = ['code'];

    /**
     * @var bool true if PKCE is disabled
     */
    private bool $unsafeDisablePkce = false;

    /**
     * @var bool true if nonce is disabled
     */
    private bool $unsafeDisableNonce = false;

    /**
     * @var bool Allow OAuth 2 implicit flow; see http://openid.net/specs/openid-connect-core-1_0.html#ImplicitFlowAuth
     */
    private bool $allowImplicitFlow = false;

    public ?string $client_name;

    // ToDo: use interface State for this
    public SessionState $state;

    public function __construct(array $wellKnownConfig = [])
    {
        /*
        * // If the configuration value is not available, attempt to fetch it from a well known config endpoint
        // This is also known as auto "discovery"
        if(!$this->wellKnown) {
            $well_known_config_url = rtrim($this->configuration->issuer, '/') . '/.well-known/openid-configuration';
            if (count($this->wellKnownConfigParameters) > 0){
                $well_known_config_url .= '?' .  http_build_query($this->wellKnownConfigParameters) ;
            }
            $this->wellKnown = json_decode($this->fetchURL($well_known_config_url));
        }

                throw new ProviderException("The provider {$param} could not be fetched. Make sure your provider has a well known configuration available.");

        */
        $this->parseConfig($wellKnownConfig);
        $this->state = new SessionState();
    }

    /**
     * @param string $url Sets redirect URL for auth flow
     */
    public function setRedirectURI(string $url) {
        if (parse_url($url,PHP_URL_HOST) !== false) {
            $this->redirect_uri = $url;
        }
    }

    public function parseConfig(array $config): void {
        $this->wellKnownConfig = $config;
        $this->issuer = $this->getWellKnownConfigValue('issuer');
    }

    /**
     * Gets the URL of the current page we are on, encodes, and returns it
     *
     * @return string
     */
    public function getRedirectURI(): string {

        // If the redirect URL has been set then return it.
        if (isset($this->redirect_uri) && $this->redirect_uri) {
            return $this->redirect_uri;
        }

        // Other-wise return the URL of the current page

        /**
         * Thank you
         * http://stackoverflow.com/questions/189113/how-do-i-get-current-page-full-url-in-php-on-a-windows-iis-server
         */

        /*
         * Compatibility with multiple host headers.
         * The problem with SSL over port 80 is resolved and non-SSL over port 443.
         * Support of 'ProxyReverse' configurations.
         */

        $protocol = @$_SERVER['HTTP_X_FORWARDED_PROTO']
            ?: @$_SERVER['REQUEST_SCHEME']
                ?: ((isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on') ? 'https' : 'http');

        $port = @intval($_SERVER['HTTP_X_FORWARDED_PORT'])
            ?: @intval($_SERVER['SERVER_PORT'])
                ?: (($protocol === 'https') ? 443 : 80);

        $host = @explode(':', $_SERVER['HTTP_HOST'])[0]
            ?: @$_SERVER['SERVER_NAME']
                ?: @$_SERVER['SERVER_ADDR'];

        $port = (443 === $port) || (80 === $port) ? '' : ':' . $port;
        
        $uriSplit = explode("?", $_SERVER['REQUEST_URI']);

        return sprintf('%s://%s%s/%s', $protocol, $host, $port, @trim(reset($uriSplit), '/'));
    }

    protected function getWellKnownConfigValue($param, $default = null): mixed {

        if (!isset($this->wellKnownConfig[$param])) {
            if($default === null) {
                throw new ProviderException("The provider config value {$param} could not be fetched.");
            }
            return $default;
        }

        return $this->wellKnownConfig[$param];
    }

    public function getJwkSet(): JWKSet
    {
        return new JWKSet($this->jwks);
    }

    /**
     * @param JWK $key
     */
    public function addJwk(JWK $key): void
    {
        $this->jwks[] = $key;
    }

    public function issParameterSupported(): bool {
        return $this->getWellKnownConfigValue('authorization_response_iss_parameter_supported', false);
    }

    /**
     * @return string
     */
    public function getCodeChallengeMethod() : string {
        $method = $this->codeChallengeMethod;

        if(empty($method)) {
            $methods = $this->getWellKnownConfigValue('code_challenge_methods_supported', []);
            if(in_array('S256', $methods)) {
                $method = 'S256';
            } elseif(in_array('plain', $methods)) {
                $method = 'plain';
            }
        }

        if(empty($method)) {
            $method = 'S256';
        }

        return $method;
    }

    /**
     * This method allows you to enforce a specific PKCE code challenge method.
     * Useful in cases where your OP supports PKCE but does not announce it in his discovery document.
     * 
     * @param string $codeChallengeMethod
     */
    public function setCodeChallengeMethod(string $codeChallengeMethod) {
        $this->codeChallengeMethod = $codeChallengeMethod;
    }

    public function getEndSessionEndpoint(): string {
        return $this->getWellKnownConfigValue('end_session_endpoint');
    }

    public function getAuthorizationEndpoint(): string {
        return $this->getWellKnownConfigValue('authorization_endpoint');
    }

    public function getTokenEndpoint(): string {
        return $this->getWellKnownConfigValue('token_endpoint');
    }

    public function getTokenEnpointAuthMethods(): array {
        return $this->getWellKnownConfigValue('token_endpoint_auth_methods_supported', ['client_secret_basic']);
    }

    public function getUserinfoEndpoint(): string {
        return $this->getWellKnownConfigValue('userinfo_endpoint');
    }

    public function getIntrospectionEndpoint(): string {
        return $this->getWellKnownConfigValue('introspection_endpoint');
    }

    public function getRevocationEndpoint(): string {
        return $this->getWellKnownConfigValue('revocation_endpoint');
    }

    public function getResponseTypes(): array {
        return $this->response_types;
    }

    public function getUnsafeDisablePkce(): bool {
        return $this->unsafeDisablePkce;
    }

    public function getJwksUri(): ?string {
        return $this->getWellKnownConfigValue('jwks_uri', null);
    }
}