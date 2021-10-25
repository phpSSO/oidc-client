<?php

use JuliusPC\OpenIDConnectClient;
use PHPUnit\Framework\TestCase;

class PkceTest extends TestCase
{
    // ToDo: More tests...
    
    public function testPkceNegotiation()
    {
        $client = $this->getMockBuilder(OpenIDConnectClient::class)->setMethods(['fetchUrl'])->getMock();
        $client->method('fetchUrl')->willReturn(file_get_contents(__DIR__ . "/data/well-known_openid-configuration.json"));
        $client->setProviderURL('https://example.org/');
        $challengeMethod = $client->getCodeChallengeMethod();
        self::assertEquals('S256', $challengeMethod);
    }
}