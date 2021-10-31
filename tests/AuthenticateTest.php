<?php

namespace JuliusPC\OpenIDConnect\Tests;

use JuliusPC\OpenIDConnect\Client;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Middleware;
use GuzzleHttp\Psr7\Response;

class AuthenticateTest extends TestBaseCase
{
    protected function setUp(): void
    {
        $_SERVER = [
            'SERVER_PROTOCOL' => 'HTTP/1.1',
            'SERVER_NAME' => 'localhost',
            'SERVER_PORT' => '8080',
            'REQUEST_URI' => '/test.php',
            'REQUEST_METHOD' => 'GET',
            'SCRIPT_NAME' => '/test.php',
            'SCRIPT_FILENAME' => '/home/user/repos/test.php',
            'PHP_SELF' => '/test.php',
            'HTTP_HOST' => 'localhost:8080',
            'HTTP_UPGRADE_INSECURE_REQUESTS' => '1'
        ];
        $_SESSION = [];
    }

    public function testAuthorizationCodeFlowRequest()
    {
        /** @var $client Client */
        $client = $this->getMockBuilder(Client::class)->setMethods(['fetchUrl', 'redirect', 'generateRandString'])->getMock();
        $client->method('fetchUrl')->willReturn(file_get_contents(__DIR__ . "/data/well-known_openid-configuration.json"));
        $client->method('generateRandString')->willReturn($this->randomToken);
        $client->method('redirect')->will($this->returnCallback(function ($url) {
            $parts = explode('?', $url);
            // check if authorization_endpoint is set correctly
            $this->assertEquals('https://example.org/connect/authorize', $parts[0]);

            // check required URL parameters
            parse_str($parts[1], $parameters);
            $this->assertEquals(7, count($parameters));
            $this->assertEquals('code', $parameters['response_type']);
            $this->assertEquals('http://localhost:8080/test.php', $parameters['redirect_uri']);
            $this->assertEquals($this->randomToken, $parameters['state']);
            $this->assertEquals('offline_access openid', $parameters['scope']);
            $this->assertEquals($this->randomToken, $parameters['nonce']);
            $this->assertEquals($this->codeChallenge, $parameters['code_challenge']);
            $this->assertEquals('S256', $parameters['code_challenge_method']);
        }));
        $client->setProviderURL('https://example.org/');
        $client->addScope(['offline_access']);
        $client->authenticate();

        // check if state, nonce, and code_verifier are saved to the session
        $this->assertEquals($this->randomToken, $_SESSION['openid_connect_state']);
        $this->assertEquals($this->randomToken, $_SESSION['openid_connect_nonce']);
        $this->assertEquals($this->randomToken, $_SESSION['openid_connect_code_verifier']);
    }

    public function testAuthorizationCodeFlowResponse()
    {
        $_SESSION['openid_connect_state'] = $this->randomToken;
        $_SESSION['openid_connect_nonce'] = $this->randomToken;
        $_SESSION['openid_connect_code_verifier'] = $this->randomToken;

        $mock = new MockHandler([
            new Response(200, ['Content-Type' => 'application/json'], file_get_contents(__DIR__ . "/data/well-known_openid-configuration.json")),
            new Response(200, ['Content-Type' => 'application/json'], '{
                "access_token": "SlAV32hkKG",
                "token_type": "Bearer",
                "refresh_token": "8xLOxBtZp8",
                "expires_in": 3600,
                "id_token": "eyJhbGciOiJSUzI1NiIsImtpZCI6IjFlOWdkazcifQ.eyJpc3MiOiJodHRwczovL2V4YW1wbGUub3JnIiwic3ViIjoiMjQ4Mjg5NzYxMDAxIiwiYXVkIjoiY2xpZW50X2lkIiwibm9uY2UiOiIwMTIzNDU2Nzg5YWJjZGVmMDEyMzQ1Njc4OWFiY2RlZiIsImV4cCI6IDEzMTEyODE5NzAsImlhdCI6MTMxMTI4MDk3MH0.ggW8hZ1EuVLuxNuuIJKX_V8a_OMXzR0EHR9R6jgdqrOOF4daGU96Sr_P6qJp6IcmD3HP99Obi1PRs-cwh3LO-p146waJ8IhehcwL7F09JdijmBqkvPeB2T9CJNqeGpe-gccMg4vfKjkM8FcGvnzZUN4_KSP0aAp1tOJ1zZwgjxqGByKHiOtX7TpdQyHE5lcMiKPXfEIQILVq0pc_E2DzL7emopWoaoZTF_m0_N0YzFC6g6EJbOEoRoSK5hoDalrcvRYLSrQAZZKflyuVCyixEoV9GfNQC3_osjzw2PAithfubEEBLuVVk4XUVrWOLrLl0nx7RkKU8NXNHq-rvKMzqg"
               }')
        ]);
        $handlerStack = HandlerStack::create($mock);
        $container = [];
        $history = Middleware::history($container);
        $handlerStack->push($history);
        $httpClient = new \GuzzleHttp\Client(['handler' => $handlerStack]);

        /** @var $client Client */
        $client = $this->getMockBuilder(Client::class)->setMethods(['verifyJWTsignature', 'verifyJWTclaims'])->getMock();
        // depending on the setup, we do not need to mock those (ToDo)
        $client->method('verifyJWTsignature')->willReturn(true);
        $client->method('verifyJWTclaims')->willReturn(true);
        $client->setProviderURL('https://example.org/');
        $client->setIssuer('https://example.org');
        $client->setClientID('client_id');
        $client->setClientSecret('client_secret');
        $client->setHttpClient($httpClient);
        $_GET['code'] = $this->authCode;
        $_GET['state'] = $this->randomToken;
        $_REQUEST = $_GET;
        $this->assertTrue($client->authenticate());

        // first request is request to the well-known document...
        $tokenRequest = $container[1]['request'];
        $this->assertEquals('https://example.org/connect/token', $tokenRequest->getUri());
        $this->assertEquals('POST', $tokenRequest->getMethod());

        // check headers
        $headers = $tokenRequest->getHeaders();
        $this->assertEquals('application/x-www-form-urlencoded', $headers['Content-Type'][0]);
        $this->assertEquals('Basic ' . base64_encode('client_id:client_secret'), $headers['Authorization'][0]);
        $this->assertEquals('example.org', $headers['Host'][0]);

        // inspect body
        parse_str($tokenRequest->getBody()->getContents(), $parameters);
        $this->assertEquals('authorization_code', $parameters['grant_type']);
        $this->assertEquals($this->authCode, $parameters['code']);
        $this->assertEquals('http://localhost:8080/test.php', $parameters['redirect_uri']);
        $this->assertEquals($this->randomToken, $parameters['code_verifier']);
        $this->assertEquals(4, count($parameters));

        // check if OpenID Connect set values correctly
        $this->assertEquals('SlAV32hkKG', $client->getAccessToken());
        $this->assertEquals('8xLOxBtZp8', $client->getRefreshToken());
        $this->assertEquals('248289761001', $client->getVerifiedClaims('sub'));
    }

    public function testAuthorizationImplicitFlowRequest()
    {
        /** @var $client Client */
        $client = $this->getMockBuilder(Client::class)->setMethods(['fetchUrl', 'redirect', 'generateRandString'])->getMock();
        $client->method('fetchUrl')->willReturn(file_get_contents(__DIR__ . "/data/well-known_openid-configuration.json"));
        $client->method('generateRandString')->willReturn($this->randomToken);
        $client->method('redirect')->will($this->returnCallback(function ($url) {
            $parts = explode('?', $url);
            // check if authorization_endpoint is set correctly
            $this->assertEquals('https://example.org/connect/authorize', $parts[0]);

            // check required URL parameters
            parse_str($parts[1], $parameters);
            $this->assertEquals(6, count($parameters));
            $this->assertEquals('id_token', $parameters['response_type']);
            $this->assertEquals('http://localhost:8080/test.php', $parameters['redirect_uri']);
            $this->assertEquals($this->randomToken, $parameters['state']);
            $this->assertEquals('openid', $parameters['scope']);
            $this->assertEquals($this->randomToken, $parameters['nonce']);

            // code_challenge and code_challenge must not be sent in implicit flow
            $this->assertArrayNotHasKey('code_challenge', $parameters);
            $this->assertArrayNotHasKey('code_challenge_method', $parameters);
        }));
        $client->setProviderURL('https://example.org/');
        $client->setResponseTypes(['id_token']);
        $client->setAllowImplicitFlow(true);
        $client->addAuthParam(['response_mode' => 'form_post']);
        $client->authenticate();

        // check if state and nonce are saved to the session
        $this->assertEquals($this->randomToken, $_SESSION['openid_connect_state']);
        $this->assertEquals($this->randomToken, $_SESSION['openid_connect_nonce']);

        // PKCE is not used in implicit flow
        $this->assertArrayNotHasKey('openid_connect_code_verifier', $_SESSION);
    }

    public function testAuthorizationImplicitFlowResponse()
    {
        $_SESSION['openid_connect_state'] = $this->randomToken;
        $_SESSION['openid_connect_nonce'] = $this->randomToken;

        $_REQUEST['id_token'] = 'eyJhbGciOiJSUzI1NiIsImtpZCI6IjFlOWdkazcifQ.eyJpc3MiOiJodHRwczovL2V4YW1wbGUub3JnIiwic3ViIjoiMjQ4Mjg5NzYxMDAxIiwiYXVkIjoiY2xpZW50X2lkIiwibm9uY2UiOiIwMTIzNDU2Nzg5YWJjZGVmMDEyMzQ1Njc4OWFiY2RlZiIsImV4cCI6IDEzMTEyODE5NzAsImlhdCI6MTMxMTI4MDk3MH0.ggW8hZ1EuVLuxNuuIJKX_V8a_OMXzR0EHR9R6jgdqrOOF4daGU96Sr_P6qJp6IcmD3HP99Obi1PRs-cwh3LO-p146waJ8IhehcwL7F09JdijmBqkvPeB2T9CJNqeGpe-gccMg4vfKjkM8FcGvnzZUN4_KSP0aAp1tOJ1zZwgjxqGByKHiOtX7TpdQyHE5lcMiKPXfEIQILVq0pc_E2DzL7emopWoaoZTF_m0_N0YzFC6g6EJbOEoRoSK5hoDalrcvRYLSrQAZZKflyuVCyixEoV9GfNQC3_osjzw2PAithfubEEBLuVVk4XUVrWOLrLl0nx7RkKU8NXNHq-rvKMzqg';
        $_REQUEST['state'] = $this->randomToken;

        /** @var $client Client */
        $client = $this->getMockBuilder(Client::class)->setMethods(['verifyJWTsignature', 'verifyJWTclaims', 'fetchURl'])->getMock();
        $client->method('fetchUrl')->willReturn(file_get_contents(__DIR__ . "/data/well-known_openid-configuration.json"));
        // depending on the setup, we do not need to mock those (ToDo)
        $client->method('verifyJWTsignature')->willReturn(true);
        $client->method('verifyJWTclaims')->willReturn(true);
        $client->setProviderURL('https://example.org/');
        $client->setResponseTypes(['id_token']);
        $client->setAllowImplicitFlow(true);
        $client->setIssuer('https://example.org');
        $client->setClientID('client_id');
        $client->setClientSecret('client_secret');
        $this->assertTrue($client->authenticate());

        // check if OpenID Connect Client set values correctly
        $this->assertEquals('248289761001', $client->getVerifiedClaims('sub'));
    }

    protected function tearDown(): void
    {
        $_SERVER = [];
        $_SESSION = [];
        $_REQUEST = [];
        $_GET = [];
        $_POST = [];
    }
}
