<?php

namespace JuliusPC\OpenIDConnect\Tests;

use PHPUnit\Framework\TestCase;

class TestBaseCase extends TestCase
{
    protected string $randomToken = '0123456789abcdef0123456789abcdef';
    protected string $codeChallenge = 'PrG9Q5lH63YpmOVmzMLgmceREYsvQFecxPfaK1Bht_k';
    protected string $authCode = 'fedcba9876543210fedcba9876543210';

    protected string $post_logout_redirect_uri = 'http://localhost:8080/post-logout.php';
    protected string $idToken = 'eyJhbGciOiJSUzI1NiIsImtpZCI6IjFlOWdkazcifQ.eyJpc3MiOiJodHRwczovL2V4YW1wbGUub3JnIiwic3ViIjoiMjQ4Mjg5NzYxMDAxIiwiYXVkIjoiY2xpZW50X2lkIiwibm9uY2UiOiIwMTIzNDU2Nzg5YWJjZGVmMDEyMzQ1Njc4OWFiY2RlZiIsImV4cCI6IDEzMTEyODE5NzAsImlhdCI6MTMxMTI4MDk3MH0.ggW8hZ1EuVLuxNuuIJKX_V8a_OMXzR0EHR9R6jgdqrOOF4daGU96Sr_P6qJp6IcmD3HP99Obi1PRs-cwh3LO-p146waJ8IhehcwL7F09JdijmBqkvPeB2T9CJNqeGpe-gccMg4vfKjkM8FcGvnzZUN4_KSP0aAp1tOJ1zZwgjxqGByKHiOtX7TpdQyHE5lcMiKPXfEIQILVq0pc_E2DzL7emopWoaoZTF_m0_N0YzFC6g6EJbOEoRoSK5hoDalrcvRYLSrQAZZKflyuVCyixEoV9GfNQC3_osjzw2PAithfubEEBLuVVk4XUVrWOLrLl0nx7RkKU8NXNHq-rvKMzqg';
    protected string $accessToken = 'SlAV32hkKG';
}
