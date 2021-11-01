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

    /**
     * @dataProvider providesHeaders
     */
    public function testRedirectURL(array $request_headers, string $expectedRedirectUri): void
    {
        $_SERVER = array_merge($_SERVER, $request_headers);
        $redirectUrl = $this->client->getRedirectURL();
        self::assertEquals($expectedRedirectUri, $redirectUrl);
    }

    public function providesHeaders()
    {
        return [
            [
                [],
                'http://localhost:8080/test.php'
            ],
            [
                [
                    'SERVER_PORT' => '80',
                    'HTTP_HOST' => 'localhost'
                ],
                'http://localhost/test.php'
            ],
            [
                [
                    'SERVER_PORT' => '80',
                    'HTTP_HOST' => 'localhost',
                    'REQUEST_URI' => '/test.php?param1=abc',
                    'QUERY_STRING' => 'param1=abc'
                ],
                'http://localhost/test.php'
            ],
            [
                [
                    'SERVER_PORT' => '443',
                    'HTTP_HOST' => 'localhost',
                    'REQUEST_SCHEME' => 'https'
                ],
                'https://localhost/test.php'
            ],
            [
                [
                    'SERVER_PORT' => '80',
                    'HTTP_HOST' => 'localhost',
                    'REQUEST_SCHEME' => 'https'
                ],
                'https://localhost/test.php'
            ],
            [
                [
                    'SERVER_PORT' => '443',
                    'HTTP_HOST' => 'localhost',
                    'HTTPS' => 'on'
                ],
                'https://localhost/test.php'
            ]
        ];
    }

    protected function tearDown(): void
    {
        $_SERVER = [];
    }
}
