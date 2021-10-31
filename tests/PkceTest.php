<?php

namespace JuliusPC\OpenIDConnect\Tests;

use JuliusPC\OpenIDConnect\Client;

class PkceTest extends TestBaseCase
{
    // ToDo: More tests...

    public function testPkceNegotiation()
    {
        /** @var $client Client */
        $client = $this->getMockBuilder(Client::class)->setMethods(['fetchUrl'])->getMock();
        $client->method('fetchUrl')->willReturn(file_get_contents(__DIR__ . "/data/well-known_openid-configuration.json"));
        $client->setProviderURL('https://example.org/');
        $challengeMethod = $client->getCodeChallengeMethod();
        self::assertEquals('S256', $challengeMethod);
    }
}
