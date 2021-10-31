<?php

namespace JuliusPC\OpenIDConnect\Tests;

use JuliusPC\OpenIDConnect\Client;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Middleware;
use GuzzleHttp\Psr7\Response;

class RefreshTokenTest extends TestBaseCase
{
    /**
     * @dataProvider providesRefreshTokens
     */
    public function testRefreshToken(string $oldRefreshToken, string $newRefreshToken, ?bool $includeScopes)
    {
        $mock = new MockHandler([
            new Response(200, ['Content-Type' => 'application/json'], file_get_contents(__DIR__ . "/data/well-known_openid-configuration.json")),
            new Response(200, ['Content-Type' => 'application/json'], '{
                "access_token": "'. $this->accessToken .'",
                "token_type": "Bearer",
                "refresh_token": "'. $newRefreshToken .'"
            }')
        ]);
        $handlerStack = HandlerStack::create($mock);
        $container = [];
        $history = Middleware::history($container);
        $handlerStack->push($history);
        $httpClient = new \GuzzleHttp\Client(['handler' => $handlerStack]);

        /** @var $client Client */
        $client = new Client('https://example.org', 'client_id', 'client_secret');
        $client->addScope('profile');
        $client->setHttpClient($httpClient);
        
        if ($includeScopes ?? false) {
            $response = $client->refreshToken($oldRefreshToken, true);
        } else {
            $response = $client->refreshToken($oldRefreshToken);
        }

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
        $this->assertEquals('refresh_token', $parameters['grant_type']);
        $this->assertEquals($oldRefreshToken, $parameters['refresh_token']);
        if($includeScopes ?? false) {
            $this->assertEquals('profile', $parameters['scope']);
        }
        $this->assertEquals(($includeScopes ?? false)? 3 : 2, count($parameters));

        // check if Client set values correctly
        $this->assertEquals($newRefreshToken, $response->refresh_token);
        $this->assertEquals($newRefreshToken, $client->getRefreshToken());
        $this->assertEquals($this->accessToken, $client->getAccessToken());
    }

    public function testRefreshTokenPostAuth()
    {
        $config = json_decode(file_get_contents(__DIR__ . "/data/well-known_openid-configuration.json"), true);
        $config['token_endpoint_auth_methods_supported'] = ['client_secret_post'];
        $mock = new MockHandler([
            new Response(200, ['Content-Type' => 'application/json'], json_encode($config)),
            new Response(200, ['Content-Type' => 'application/json'], '{
                "access_token": "access_token",
                "token_type": "Bearer",
                "refresh_token": "refresh_token"
            }')
        ]);
        $handlerStack = HandlerStack::create($mock);
        $container = [];
        $history = Middleware::history($container);
        $handlerStack->push($history);
        $httpClient = new \GuzzleHttp\Client(['handler' => $handlerStack]);

        /** @var $client Client */
        $client = new Client('https://example.org', 'client_id', 'client_secret');
        $client->addScope('profile');
        $client->setHttpClient($httpClient);

        $client->refreshToken('refresh_token', false);

        // first request is request to the well-known document...
        $tokenRequest = $container[1]['request'];
        $this->assertEquals('https://example.org/connect/token', $tokenRequest->getUri());
        $this->assertEquals('POST', $tokenRequest->getMethod());

        // check headers
        $headers = $tokenRequest->getHeaders();
        $this->assertEquals('application/x-www-form-urlencoded', $headers['Content-Type'][0]);
        $this->assertArrayNotHasKey('Authorization', $headers);
        $this->assertEquals('example.org', $headers['Host'][0]);

        // inspect body
        parse_str($tokenRequest->getBody()->getContents(), $parameters);
        $this->assertEquals('refresh_token', $parameters['grant_type']);
        $this->assertEquals('refresh_token', $parameters['refresh_token']);
        $this->assertEquals('client_id', $parameters['client_id']);
        $this->assertEquals('client_secret', $parameters['client_secret']);
        $this->assertEquals(4, count($parameters));
    }

    public function providesRefreshTokens()
    {
        return [
            ['8xLOxBtZp8', '8xLOxBtZp8', null],
            ['8xLOxBtZp8', 'Li6AhNa9tF', null],
            ['8xLOxBtZp8', '8xLOxBtZp8', true],
            ['8xLOxBtZp8', 'Li6AhNa9tF', true]
        ];
    }
}
