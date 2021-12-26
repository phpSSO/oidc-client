<?php

namespace JuliusPC\OpenIDConnect;

use GuzzleHttp\ClientInterface;
use GuzzleHttp\RetryMiddleware;
use Jose\Component\Core\JWKSet;
use JuliusPC\OpenIDConnect\Client;
use JuliusPC\OpenIDConnect\Configuration;
use Jose\Component\KeyManagement\JWKFactory;
use JuliusPC\OpenIDConnect\Exceptions\ClientException;
use JuliusPC\OpenIDConnect\SessionState;

class ClientFactory
{
    public static function client(string $issuer, string $client_id, string $client_secret): Client
    {
        $issuer = self::validateAndSanitizeIssuer($issuer);
        $httpClient = self::createHttpClient();
        $config = new Configuration(self::getDiscoveryDocument($issuer, $httpClient));
        $config->client_id = $client_id;
        $config->client_secret = $client_secret;

        $jwksUri = $config->getJwksUri();
        if ($jwksUri != null) {
            $keySet = self::getJwksFromUri($jwksUri, $httpClient);
            foreach($keySet as $key) {
                $config->addJwk($key);
            }
        }
        $config->addJwk(JWKFactory::createFromSecret($client_secret));

        return new Client($config, $httpClient, new SessionState());
    }

    //public abstract static function implicitClient(): Client;

    /**
     * @return array{
     * client: Client,
     * client_id: string,
     * client_secret: string
     * }
     */
    //public abstract static function dynamicRegisterClient(string $issuer): array;

    /**
     * Dynamic registration
     *
     * @throws ClientException
     */
    /*    /**
     * @param $registrationParams array holds additional registration parameters for example post_logout_redirect_uris
    public function register(array $registrationParams = []) {

        $registration_endpoint = $this->getProviderConfigValue('registration_endpoint');

        $send_object = (object ) array_merge($this->registrationParams, [
            'redirect_uris' => [$this->getRedirectURL()],
            'client_name' => $this->configuration->client_name
        ]);

        $response = $this->fetchURL($registration_endpoint, json_encode($send_object));

        $json_response = json_decode($response);

        // Throw some errors if we encounter them
        if ($json_response === false) {
            throw new ClientException('Error registering: JSON response received from the server was invalid.');
        }

        if (isset($json_response->{'error_description'})) {
            throw new ClientException($json_response->{'error_description'});
        }

        $this->configuration->client_id = $json_response->{'client_id'};

        // The OpenID Connect Dynamic registration protocol makes the client secret optional
        // and provides a registration access token and URI endpoint if it is not present
        if (isset($json_response->{'client_secret'})) {
            $this->configuration->client_secret = $json_response->{'client_secret'};
        } else {
            throw new ClientException('Error registering:
                                                    Please contact the OpenID Connect provider and obtain a Client ID and Secret directly from them');
        }
    }*/

    //public abstract static function discoverIssuer(): string;

    /**
     * @return ClientInterface
     */
    protected static function createHttpClient(): ClientInterface
    {
        $options = [
            'allow_redirects' => true,
            'timeout' => 30
        ];
        return new \GuzzleHttp\Client($options);
    }

    protected static function validateAndSanitizeIssuer(string $issuer): string
    {
        if (filter_var($issuer, FILTER_VALIDATE_URL)) {
            $scheme = strtolower(parse_url($issuer, PHP_URL_SCHEME));

            if ($scheme == 'https' || $scheme == 'http') {
                return rtrim($issuer, "\t\r\n\0\x0B/");
            }
        }

        throw new ClientException("issuer must be a valid http oder https URL");
    }

    protected static function getDiscoveryDocument(string $issuer, ClientInterface $httpClient): array
    {
        $oidcConfig = $httpClient->request('GET', "{$issuer}/.well-known/openid-configuration");
        if ($oidcConfig->getStatusCode() != 200 || !str_starts_with($oidcConfig->getHeader('Content-Type')[0], 'application/json')) {
            throw new ClientException("OIDC Discovery document could not be fetched");
        }
        try {
            $oidcConfig = json_decode($oidcConfig->getBody(), JSON_THROW_ON_ERROR | JSON_OBJECT_AS_ARRAY);
        } catch (\JsonException $e) {
            throw new ClientException("Parsing the OIDC Discovery document failed.", 0, $e);
        }
        return $oidcConfig;
    }

    protected static function getJwksFromUri(string $jwksUri, ClientInterface $httpClient): JWKSet
    {
        $jwks = $httpClient->request('GET', $jwksUri);
        if ($jwks->getStatusCode() != 200 || !str_starts_with($jwks->getHeader('Content-Type')[0], 'application/json')) {
            throw new ClientException("JWK document could not be fetched");
        }
        return JWKSet::createFromJson($jwks->getBody()->getContents());
    }
}

//$issuer = 'https://example.org';
//list($client, $client_id, $client_secret) = ClientFactory::dynamicRegisterClient($issuer);