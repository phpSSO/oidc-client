<?php

namespace JuliusPC\OpenIDConnect\Tests;

use JuliusPC\OpenIDConnect\Client;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Middleware;
use GuzzleHttp\Psr7\Response;

class UserInfoTest extends TestBaseCase
{
    /**
     * @dataProvider providesSub
     */
    public function testUserInfo(?string $sub, ?string $exception): void
    {
        $_SESSION = [];
        $userinfo = json_decode(file_get_contents(__DIR__ . "/data/userinfo-response.json"), true);
        if(!empty($sub)) {
            $userinfo['sub'] = $sub;
        } else {
            unset($userinfo['sub']);
        }
        $mock = new MockHandler([
            new Response(200, ['Content-Type' => 'application/json'], file_get_contents(__DIR__ . "/data/well-known_openid-configuration.json")),
            new Response(200, ['Content-Type' => 'application/json'], json_encode($userinfo))
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
        $client->setHttpClient($httpClient);
        $client->setProviderURL('https://example.org/');
        $client->setIssuer('https://example.org');
        $client->setClientID('client_id');
        $client->setClientSecret('client_secret');
        $client->setAccessToken($this->accessToken);
        $client->setIdToken($this->idToken);

        if(!empty($exception)) {
            $this->expectException($exception);
        }

        // act & assert
        $receivedUserinfo = $client->requestUserInfo();
        $this->assertEquals(count($userinfo), count((array)$receivedUserinfo));
        $receivedSub = $client->requestUserInfo('sub');
        $this->assertEquals($sub, $receivedSub);

        // first request is request to the well-known document...
        $tokenRequest = $container[1]['request'];
        $this->assertEquals('https://example.org/connect/userinfo', $tokenRequest->getUri());
        $this->assertEquals('GET', $tokenRequest->getMethod());

        // check headers
        $headers = $tokenRequest->getHeaders();
        $this->assertEquals('application/json', $headers['Accept'][0]);
        $this->assertEquals('Bearer ' . $this->accessToken, $headers['Authorization'][0]);
        $this->assertEquals('example.org', $headers['Host'][0]);
    }

    public function providesSub(): array
    {
        return [
            // this sub matches the one in the ID Token
            ['248289761001', null],
            // sub must be set
            [null, '\JuliusPC\OpenIDConnect\Exceptions\ClientException'],
            // this sub does not match with the one in the ID Token
            ['248289761abcdef', '\JuliusPC\OpenIDConnect\Exceptions\ClientException']
        ];
    }
}
