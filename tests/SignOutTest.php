<?php

use JuliusPC\OpenIDConnectClient;
use PHPUnit\Framework\TestCase;

class SignOutTest extends TestCase
{
    private string $post_logout_redirect_uri = 'http://localhost:8080/post-logout.php';
    private string $id_token = 'eyJhbGciOiJSUzI1NiIsImtpZCI6IjFlOWdkazcifQ.eyJpc3MiOiJodHRwczovL2V4YW1wbGUub3JnIiwic3ViIjoiMjQ4Mjg5NzYxMDAxIiwiYXVkIjoiY2xpZW50X2lkIiwibm9uY2UiOiIwMTIzNDU2Nzg5YWJjZGVmMDEyMzQ1Njc4OWFiY2RlZiIsImV4cCI6IDEzMTEyODE5NzAsImlhdCI6MTMxMTI4MDk3MH0.ggW8hZ1EuVLuxNuuIJKX_V8a_OMXzR0EHR9R6jgdqrOOF4daGU96Sr_P6qJp6IcmD3HP99Obi1PRs-cwh3LO-p146waJ8IhehcwL7F09JdijmBqkvPeB2T9CJNqeGpe-gccMg4vfKjkM8FcGvnzZUN4_KSP0aAp1tOJ1zZwgjxqGByKHiOtX7TpdQyHE5lcMiKPXfEIQILVq0pc_E2DzL7emopWoaoZTF_m0_N0YzFC6g6EJbOEoRoSK5hoDalrcvRYLSrQAZZKflyuVCyixEoV9GfNQC3_osjzw2PAithfubEEBLuVVk4XUVrWOLrLl0nx7RkKU8NXNHq-rvKMzqg';

    public function testSignOutWithPostLogoutRedirectUri() : void
    {
        /** @var $client OpenIDConnectClient */
        $client = $this->getMockBuilder(OpenIDConnectClient::class)->setMethods(['fetchUrl', 'redirect'])->getMock();
        $client->method('fetchUrl')->willReturn(file_get_contents(__DIR__ . "/data/well-known_openid-configuration.json"));
        $client->method('redirect')->will($this->returnCallback(function($url) {
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

    public function testSignOutWithoutPostLogoutRedirectUri() : void
    {
        /** @var $client OpenIDConnectClient */
        $client = $this->getMockBuilder(OpenIDConnectClient::class)->setMethods(['fetchUrl', 'redirect'])->getMock();
        $client->method('fetchUrl')->willReturn(file_get_contents(__DIR__ . "/data/well-known_openid-configuration.json"));
        $client->method('redirect')->will($this->returnCallback(function($url) {
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
}