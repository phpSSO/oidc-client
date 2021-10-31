<?php

namespace JuliusPC\OpenIDConnect\Tests;

use JuliusPC\OpenIDConnect\Client;

class SignOutTest extends TestBaseCase
{
    public function testSignOutWithPostLogoutRedirectUri(): void
    {
        /** @var $client Client */
        $client = $this->getMockBuilder(Client::class)->setMethods(['fetchUrl', 'redirect'])->getMock();
        $client->method('fetchUrl')->willReturn(file_get_contents(__DIR__ . "/data/well-known_openid-configuration.json"));
        $client->method('redirect')->will($this->returnCallback(function ($url) {
            $parts = explode('?', $url);
            // check if authorization_endpoint is set correctly
            $this->assertEquals('https://example.org/connect/endsession', $parts[0]);

            // check required URL parameters
            parse_str($parts[1], $parameters);
            $this->assertEquals(2, count($parameters));
            $this->assertEquals($this->id_token, $parameters['id_token_hint']);
            $this->assertEquals($this->post_logout_redirect_uri, $parameters['post_logout_redirect_uri']);
        }));
        $client->setProviderURL('https://example.org/');
        $client->signOut($this->id_token, $this->post_logout_redirect_uri);
    }

    public function testSignOutWithoutPostLogoutRedirectUri(): void
    {
        /** @var $client Client */
        $client = $this->getMockBuilder(Client::class)->setMethods(['fetchUrl', 'redirect'])->getMock();
        $client->method('fetchUrl')->willReturn(file_get_contents(__DIR__ . "/data/well-known_openid-configuration.json"));
        $client->method('redirect')->will($this->returnCallback(function ($url) {
            $parts = explode('?', $url);
            // check if authorization_endpoint is set correctly
            $this->assertEquals('https://example.org/connect/endsession', $parts[0]);

            // check required URL parameters
            parse_str($parts[1], $parameters);
            $this->assertEquals(1, count($parameters));
            $this->assertEquals($this->id_token, $parameters['id_token_hint']);
        }));
        $client->setProviderURL('https://example.org/');
        $client->signOut($this->id_token, null);
    }

    public function testSignOutWithoutEndsessionEndpoint(): void
    {
        /** @var $client Client */
        $client = $this->getMockBuilder(Client::class)->setMethods(['fetchUrl', 'redirect'])->getMock();
        $config = file_get_contents(__DIR__ . "/data/well-known_openid-configuration.json");
        $config = json_decode($config, true);
        unset($config['end_session_endpoint']);

        $client->method('fetchUrl')->willReturn(json_encode($config));
        $client->setProviderURL('https://example.org/');
        $this->expectException('\JuliusPC\OpenIDConnect\Exceptions\ProviderException');
        $client->signOut($this->id_token, null);
    }
}
