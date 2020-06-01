<?php

namespace eIDASCertificate\tests;

use PHPUnit\Framework\TestCase;
use eIDASCertificate\OCSP\OCSPRequest;
use eIDASCertificate\OCSP\CertID;
use eIDASCertificate\OCSP\Request;
use eIDASCertificate\OCSP\TBSRequest;
use eIDASCertificate\OCSP\OCSPNonce;
use eIDASCertificate\Extension;
use eIDASCertificate\AlgorithmIdentifier;
use eIDASCertificate\tests\Helper;
use ASN1\Type\UnspecifiedType;

class OCSPTest extends TestCase
{
    private $requestDER;

    const eucrtfile = 'European-Commission.crt';
    const qvcrtfile = 'qvbecag2.crt';
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
        $ocspNonce = OCSPNonce::fromValue($nonce);

        $this->assertEquals(
            base64_encode($der),
            base64_encode($ocspNonce->getBinary())
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
            'a85d4c6820beff673073658e163c2f9d',
            $certId->getSerialNumber()
        );
        $this->assertEquals(
            [
            'serialNumber' => 'a85d4c6820beff673073658e163c2f9d',
            'algorithmName' => 'sha-1',
            'issuerKeyHash' => '82af6c8cf8c5fe96617ce81f3d2b71485ec48bc0',
            'issuerNameHash' => 'c4c3dd52a50e02dd3c949825b7295ad3aec64b3e'
          ],
            $certId->getAttributes()
        );
    }

    public function testCertId()
    {
        $newCertId = new CertID(
            'sha-1',
            hex2bin('c4c3dd52a50e02dd3c949825b7295ad3aec64b3e'),
            hex2bin('82af6c8cf8c5fe96617ce81f3d2b71485ec48bc0'),
            'a85d4c6820beff673073658e163c2f9d'
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
            'a85d4c6820beff673073658e163c2f9d',
            $newCertId->getSerialNumber()
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

        $der256 = base64_decode(
            'MGswaTANBglghkgBZQMEAgEFAAQgfysBnapRzSv9UvTcZjk5Ke1jchA+E3HKPB+ww'.
            'UY7f+0EIJ5QbubkHbawfwOOeGZLQ1v63Qs6Y/snXWEeFh+6bqIwAhRZdy5wBmm3Zp'.
            '+wEsXN0Tw6KBoJEQ=='
        );
        $request = Request::fromDER($der256);
        $this->assertEquals(
            base64_encode($der256),
            base64_encode($request->getBinary())
        );
        $this->assertEquals(
            [
            'serialNumber' => '59772e700669b7669fb012c5cdd13c3a281a0911',
            'algorithmName' => 'sha-256',
            'issuerKeyHash' => '9e506ee6e41db6b07f038e78664b435bfadd0b3a63fb275d611e161fba6ea230',
            'issuerNameHash' => '7f2b019daa51cd2bfd52f4dc66393929ed6372103e1371ca3c1fb0c1463b7fed'
          ],
            $request->getAttributes()
        );
    }

    public function testTBSRequestfromDER()
    {
        $tbsRequest = TBSRequest::fromDER($this->tbsRequestDER);
        $this->assertEquals(
            base64_encode($this->tbsRequestDER),
            base64_encode($tbsRequest->getBinary())
        );
        $this->assertEquals(
            '6b10b2e654dd598ac463315262911aed',
            bin2hex($tbsRequest->getNonce())
        );
    }

    public function testOCSPRequest()
    {
        $issuerNameHash = hex2bin('7F2B019DAA51CD2BFD52F4DC66393929ED6372103E1371CA3C1FB0C1463B7FED');
        $issuerKeyHash = hex2bin('9E506EE6E41DB6B07F038E78664B435BFADD0B3A63FB275D611E161FBA6EA230');
        $serialNumber = '59772E700669B7669FB012C5CDD13C3A281A0911';
        $nonce = hex2bin('CC51FED1358BCAB2F2F345797A295D8D');
        $req = new OCSPRequest(
            'sha-256',
            $issuerNameHash,
            $issuerKeyHash,
            $serialNumber,
            $nonce
        );
        $this->assertEquals(
            'MIGXMIGUMG0wazBpMA0GCWCGSAFlAwQCAQUABCB/KwGdqlHNK/1S9NxmOTkp7WNyED'.
          '4Tcco8H7DBRjt/7QQgnlBu5uQdtrB/A454ZktDW/rdCzpj+yddYR4WH7puojACFFl3'.
          'LnAGabdmn7ASxc3RPDooGgkRoiMwITAfBgkrBgEFBQcwAQIEEgQQzFH+0TWLyrLy80'.
          'V5eildjQ==',
            base64_encode($req->getBinary())
        );
        $nonce = hex2bin('6b10b2e654dd598ac463315262911aed');
        $req = new OCSPRequest(
            'sha-256',
            $issuerNameHash,
            $issuerKeyHash,
            $serialNumber,
            $nonce
        );
        $this->assertEquals(
            'MIGXMIGUMG0wazBpMA0GCWCGSAFlAwQCAQUABCB/KwGdqlHNK/1S9NxmOTkp7WNyED'.
          '4Tcco8H7DBRjt/7QQgnlBu5uQdtrB/A454ZktDW/rdCzpj+yddYR4WH7puojACFFl3'.
          'LnAGabdmn7ASxc3RPDooGgkRoiMwITAfBgkrBgEFBQcwAQIEEgQQaxCy5lTdWYrEYz'.
          'FSYpEa7Q==',
            base64_encode($req->getBinary())
        );
        $this->assertEquals(
            [
            'version' => 1,
            'requests' => [
              [
                'serialNumber' => '59772e700669b7669fb012c5cdd13c3a281a0911',
                'algorithmName' => 'sha-256',
                'issuerKeyHash' => '9e506ee6e41db6b07f038e78664b435bfadd0b3a63fb275d611e161fba6ea230',
                'issuerNameHash' => '7f2b019daa51cd2bfd52f4dc66393929ed6372103e1371ca3c1fb0c1463b7fed'
              ],
            ],
            'nonce' => '6b10b2e654dd598ac463315262911aed'
          ],
            $req->getAttributes()
        );
    }

    public function testOCSPRequestFromDER()
    {
        $der = file_get_contents(__DIR__ .'/ocsp/request-sha256');
        $request = OCSPRequest::fromDER($der);
        $this->assertEquals(
            'cc51fed1358bcab2f2f345797a295d8d',
            bin2hex($request->getNonce())
        );
        $this->assertEquals(
            '9e506ee6e41db6b07f038e78664b435bfadd0b3a63fb275d611e161fba6ea230',
            bin2hex($request->getRequests()[0]->getIssuerKeyHash())
        );
        $this->assertEquals(
            '7f2b019daa51cd2bfd52f4dc66393929ed6372103e1371ca3c1fb0c1463b7fed',
            bin2hex($request->getRequests()[0]->getIssuerNameHash())
        );
        $this->assertEquals(
            '59772e700669b7669fb012c5cdd13c3a281a0911',
            $request->getRequests()[0]->getSerialNumber()
        );
        $this->assertEquals(
            [
            'version' => 1,
            'requests' => [
              [
                'serialNumber' => '59772e700669b7669fb012c5cdd13c3a281a0911',
                'algorithmName' => 'sha-256',
                'issuerKeyHash' => '9e506ee6e41db6b07f038e78664b435bfadd0b3a63fb275d611e161fba6ea230',
                'issuerNameHash' => '7f2b019daa51cd2bfd52f4dc66393929ed6372103e1371ca3c1fb0c1463b7fed'
              ],
            ],
            'nonce' => 'cc51fed1358bcab2f2f345797a295d8d'
          ],
            $request->getAttributes()
        );
    }

    public function testOCSPRequestFromCertificate()
    {
        $eucrtPEM = file_get_contents(
            __DIR__ . "/certs/" . self::eucrtfile
        );

        $req = OCSPRequest::fromCertificate(
            file_get_contents(__DIR__ . '/certs/' . self::eucrtfile),
            file_get_contents(__DIR__ . '/certs/' . self::qvcrtfile),
            'sha256',
            hex2bin('cc51fed1358bcab2f2f345797a295d8d')
        );
        $this->assertEquals(
            [
                'version' => 1,
                'requests' => [
                  [
                    'serialNumber' => '59772e700669b7669fb012c5cdd13c3a281a0911',
                    'algorithmName' => 'sha-256',
                    'issuerKeyHash' => '9e506ee6e41db6b07f038e78664b435bfadd0b3a63fb275d611e161fba6ea230',
                    'issuerNameHash' => '7f2b019daa51cd2bfd52f4dc66393929ed6372103e1371ca3c1fb0c1463b7fed'
                  ],
                ],
                'nonce' => 'cc51fed1358bcab2f2f345797a295d8d'
            ],
            $req->getAttributes()
        );
        $this->assertEquals(
            'MIGXMIGUMG0wazBpMA0GCWCGSAFlAwQCAQUABCB/KwGdqlHNK/1S9NxmOTkp7WNyE'.
            'D4Tcco8H7DBRjt/7QQgnlBu5uQdtrB/A454ZktDW/rdCzpj+yddYR4WH7puojACFF'.
            'l3LnAGabdmn7ASxc3RPDooGgkRoiMwITAfBgkrBgEFBQcwAQIEEgQQzFH+0TWLyrL'.
            'y80V5eildjQ==',
            base64_encode($req->getBinary())
        );
    }
}
