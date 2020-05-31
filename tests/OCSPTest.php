<?php

namespace eIDASCertificate\tests;

use PHPUnit\Framework\TestCase;
use eIDASCertificate\OCSP\OCSPRequest;
use eIDASCertificate\OCSP\CertID;
use eIDASCertificate\OCSP\Request;
use eIDASCertificate\OCSP\TBSRequest;
use eIDASCertificate\OCSP\OCSPNonce;
use eIDASCertificate\Certificate\Extension;
use eIDASCertificate\AlgorithmIdentifier;
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
        $this->tbsRequestDER = base64_decode(
            'MHUwTjBMMEowCQYFKw4DAhoFAAQUxMPdUqUOAt08lJgltyla067GSz4EFIKvbIz4xf6'.
            'WYXzoHz0rcUhexIvAAhEAqF1MaCC+/2cwc2WOFjwvnaIjMCEwHwYJKwYBBQUHMAECBB'.
            'IEEGsQsuZU3VmKxGMxUmKRGu0='
        );
        $this->certIdDER = base64_decode(
            'MEowCQYFKw4DAhoFAAQUxMPdUqUOAt08lJgltyla067GSz4EFIKvbIz4xf6WYXzoH'.
            'z0rcUhexIvAAhEAqF1MaCC+/2cwc2WOFjwvnQ=='
        );
    }

    public function testOCSPNonce()
    {
        $nonce = hex2bin('6b10b2e654dd598ac463315262911aed');
        $der = base64_decode(
            'MB8GCSsGAQUFBzABAgQSBBBrELLmVN1ZisRjMVJikRrt'
        );
        $ocspNonce = Extension::fromBinary($der);
        $this->assertEquals(
            bin2hex($nonce),
            bin2hex($ocspNonce->getNonce())
        );
        $this->assertEquals(
            base64_encode($der),
            base64_encode($ocspNonce->getBinary())
        );
        $this->assertEquals(
            bin2hex(OCSPNonce::fromValue($nonce)->getBinary()),
            bin2hex($ocspNonce->getBinary())
        );
    }
    public function testCertIdFromDER()
    {
        $certId = CertID::fromDER($this->certIdDER);
        $this->assertEquals(
            '1.3.14.3.2.26',
            $certId->getAlgorithmOID()
        );
        $this->assertEquals(
            'sha-1',
            $certId->getAlgorithmName()
        );
        $this->assertEquals(
            '82af6c8cf8c5fe96617ce81f3d2b71485ec48bc0',
            bin2hex($certId->getIssuerKeyHash())
        );
        $this->assertEquals(
            'c4c3dd52a50e02dd3c949825b7295ad3aec64b3e',
            bin2hex($certId->getIssuerNameHash())
        );
        $this->assertEquals(
            '323233373934373336363132373032383036393534373035303930383936343539343736383933',
            bin2hex($certId->getSerialNumber())
        );
    }

    public function testCertId()
    {
        $newCertId = new CertID(
            'sha-1',
            hex2bin('c4c3dd52a50e02dd3c949825b7295ad3aec64b3e'),
            hex2bin('82af6c8cf8c5fe96617ce81f3d2b71485ec48bc0'),
            hex2bin('323233373934373336363132373032383036393534373035303930383936343539343736383933')
        );
        $this->assertEquals(
            '1.3.14.3.2.26',
            $newCertId->getAlgorithmOID()
        );
        $this->assertEquals(
            'sha-1',
            $newCertId->getAlgorithmName()
        );
        $this->assertEquals(
            '82af6c8cf8c5fe96617ce81f3d2b71485ec48bc0',
            bin2hex($newCertId->getIssuerKeyHash())
        );
        $this->assertEquals(
            'c4c3dd52a50e02dd3c949825b7295ad3aec64b3e',
            bin2hex($newCertId->getIssuerNameHash())
        );
        $this->assertEquals(
            '323233373934373336363132373032383036393534373035303930383936343539343736383933',
            bin2hex($newCertId->getSerialNumber())
        );
        $this->assertEquals(
            base64_encode($this->certIdDER),
            base64_encode($newCertId->getBinary())
        );
    }

    public function testRequestfromDER()
    {
        $der = base64_decode(
            'MEwwSjAJBgUrDgMCGgUABBTEw91SpQ4C3TyUmCW3KVrTrsZLPgQUgq9sjPjF/pZhfO'.
          'gfPStxSF7Ei8ACEQCoXUxoIL7/ZzBzZY4WPC+d'
        );
        $request = Request::fromDER($der);
        $this->assertEquals(
            base64_encode($der),
            base64_encode($request->getBinary())
        );
    }

    public function testTBSRequestfromDER()
    {
        $tbsRequest = TBSRequest::fromDER($this->tbsRequestDER);
        $this->assertEquals(
            base64_encode($this->tbsRequestDER),
            base64_encode($tbsRequest->getBinary())
        );
    }

    public function testOCSPRequestFromDER()
    {
        $requestParsed = OCSPRequest::fromDER($this->requestDER);
    }

    public function testOCSPRequest()
    {
        $req = new OCSPRequest;
        $this->assertEquals(
            'MAIwAA==',
            base64_encode($req->getBinary())
        );
    }
}
