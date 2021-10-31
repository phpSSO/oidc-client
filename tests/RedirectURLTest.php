<?php

namespace JuliusPC\OpenIDConnect\Tests;

use JuliusPC\OpenIDConnect\Client;

class RedirectURLTest extends TestBaseCase
{
    private Client $client;

    protected function setUp(): void
    {
        $this->client = new Client('https://example.org', 'client_id', 'client_secret');
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
    }

    public function testRedirectURLHttp8080(): void
    {
        $redirectUrl = $this->client->getRedirectURL();
        self::assertEquals('http://localhost:8080/test.php', $redirectUrl);
    }

    public function testRedirectURLHttp80(): void
    {
        $_SERVER['SERVER_PORT'] = '80';
        $_SERVER['HTTP_HOST'] = 'localhost';

        $redirectUrl = $this->client->getRedirectURL();
        self::assertEquals('http://localhost/test.php', $redirectUrl);
    }

    public function testRedirectURLQueryParameter(): void
    {
        $_SERVER['SERVER_PORT'] = '80';
        $_SERVER['HTTP_HOST'] = 'localhost';
        $_SERVER['REQUEST_URI'] = '/test.php?param1=abc';
        $_SERVER['QUERY_STRING'] = 'param1=abc';

        $redirectUrl = $this->client->getRedirectURL();
        self::assertEquals('http://localhost/test.php', $redirectUrl);
    }

    public function testRedirectURLHttpsRequestScheme(): void
    {
        $_SERVER['SERVER_PORT'] = '443';
        $_SERVER['HTTP_HOST'] = 'localhost:443';
        $_SERVER['REQUEST_SCHEME'] = 'https';

        $redirectUrl = $this->client->getRedirectURL();
        self::assertEquals('https://localhost/test.php', $redirectUrl);
    }

    public function testRedirectURLHttpsXForwardedProto(): void
    {
        $_SERVER['SERVER_PORT'] = '80';
        $_SERVER['HTTP_HOST'] = 'localhost:80';
        $_SERVER['HTTP_X_FORWARDED_PROTO'] = 'https';

        $redirectUrl = $this->client->getRedirectURL();
        self::assertEquals('https://localhost/test.php', $redirectUrl);
    }

    public function testRedirectURLHttpsHeader(): void
    {
        $_SERVER['SERVER_PORT'] = '443';
        $_SERVER['HTTP_HOST'] = 'localhost:443';
        $_SERVER['HTTPS'] = 'on';

        $redirectUrl = $this->client->getRedirectURL();
        self::assertEquals('https://localhost/test.php', $redirectUrl);
    }

    protected function tearDown(): void
    {
        $_SERVER = [];
    }
}
