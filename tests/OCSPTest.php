<?php

namespace eIDASCertificate\tests;

use PHPUnit\Framework\TestCase;
use eIDASCertificate\OCSP\OCSPRequest;
use eIDASCertificate\OCSP\CertID;
use eIDASCertificate\tests\Helper;

class OCSPTest extends TestCase
{
    private $requestDER;

    public function setUp()
    {
        $this->requestDER = base64_decode(
            'MHcwdTBOMEwwSjAJBgUrDgMCGgUABBTEw91SpQ4C3TyUmCW3KVrTrsZLPgQUgq9sjPjF/pZ'.
        'hfOgfPStxSF7Ei8ACEQCoXUxoIL7/ZzBzZY4WPC+doiMwITAfBgkrBgEFBQcwAQIEEgQQax'.
        'Cy5lTdWYrEYzFSYpEa7Q=='
        );
    }

    public function testOCSPRequestFromDER()
    {
        $requestParsed = OCSPRequest::fromDER($this->requestDER);
        $this->assertEquals(
            [
        'requestHash' => '73f197027ae555b8ecb60a488ca89510ed3b57922ba43315bdabb7290f6e3c07',
        'b64' => [
          'OCSPRequest' => base64_encode($this->requestDER),
          'tbsRequest' => 'MHUwTjBMMEowCQYFKw4DAhoFAAQUxMPdUqUOAt08lJgltyla067GSz4EFIKvbIz4xf6WYXzoHz0rcUhexIvAAhEAqF1MaCC+/2cwc2WOFjwvnaIjMCEwHwYJKwYBBQUHMAECBBIEEGsQsuZU3VmKxGMxUmKRGu0=',
          'extensions' => 'MCEwHwYJKwYBBQUHMAECBBIEEGsQsuZU3VmKxGMxUmKRGu0=',
          'requestList' => 'ME4wTDBKMAkGBSsOAwIaBQAEFMTD3VKlDgLdPJSYJbcpWtOuxks+BBSCr2yM+MX+lmF86B89K3FIXsSLwAIRAKhdTGggvv9nMHNljhY8L50=',
          'requests' => [
            'MEwwSjAJBgUrDgMCGgUABBTEw91SpQ4C3TyUmCW3KVrTrsZLPgQUgq9sjPjF/pZhfOgfPStxSF7Ei8ACEQCoXUxoIL7/ZzBzZY4WPC+d'

          ],
        ],
        'requests' => [
          base64_decode('MEwwSjAJBgUrDgMCGgUABBTEw91SpQ4C3TyUmCW3KVrTrsZLPgQUgq9sjPjF/pZhfOgfPStxSF7Ei8ACEQCoXUxoIL7/ZzBzZY4WPC+d')
        ]
      ],
            $requestParsed
        );
    }

    public function testOCSPRequest()
    {
        $req = new OCSPRequest;
        $this->assertEquals(
            'MAIwAA==',
            base64_encode($req->getBinary())
        );
    }

    public function testCertId()
    {
        $certId = CertID::fromDER(
            base64_decode('MEwwSjAJBgUrDgMCGgUABBTEw91SpQ4C3TyUmCW3KVrTrsZLPgQUgq9sjPjF/pZhfOgfPStxSF7Ei8ACEQCoXUxoIL7/ZzBzZY4WPC+d')
        );
    }
}
