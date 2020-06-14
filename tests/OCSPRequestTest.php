<?php

namespace eIDASCertificate\tests;

use PHPUnit\Framework\TestCase;
use eIDASCertificate\Certificate\X509Certificate;
use eIDASCertificate\OCSP\OCSPRequest;
use eIDASCertificate\OCSP\CertID;
use eIDASCertificate\OCSP\Request;
use eIDASCertificate\OCSP\TBSRequest;
use eIDASCertificate\OCSP\OCSPNonce;
use eIDASCertificate\Extension;
use eIDASCertificate\AlgorithmIdentifier;
use ASN1\Type\UnspecifiedType;

class OCSPTest extends TestCase
{
    private $requestDER;

    const eucrtfile = 'European-Commission.crt';
    const qvcrtfile = 'qvbecag2.crt';
    const itsmecrtfile = 'itsme-Sign-Issuing-G1.crt';
    const qventca1g3crtfile = 'qventca1g3.crt';

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
            OCSPCommonTest::certId5977SHA256,
            $request->getAttributes()
        );

        $this->assertEquals(
            '92fab49b04e6f07b7005ed6f79a9137bbfe8ad46a3ab216153ea0de6662d6e1d',
            bin2hex($request->getCertIdIdentifier())
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

        $this->assertEquals(
            '63709a738f3c5872eefac26b4bd3bc7fa8ad7a486afa5d2c2388f4d27b8124dc',
            bin2hex($tbsRequest->getRequestIdentifier())
        );
        $this->assertEquals(
            [hex2bin('39c0f4d655b00d944a23187174a5f7c7b5b356b4f4c3981e8c86fec744e69a42')],
            $tbsRequest->getCertIdIdentifiers()
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
            'requests' => [OCSPCommonTest::certId5977SHA256],
            'nonce' => '6b10b2e654dd598ac463315262911aed'
          ],
            $req->getAttributes()
        );

        $this->assertEquals(
            'e2ac8169783e498574836df97f7de700037c0cf2dc12cd30f9d55654bc04f3aa',
            bin2hex($req->getRequestIdentifier())
        );
        $this->assertEquals(
            [hex2bin('92fab49b04e6f07b7005ed6f79a9137bbfe8ad46a3ab216153ea0de6662d6e1d')],
            $req->getCertIdIdentifiers()
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
        $reqs = $request->getRequests();
        $this->assertEquals(
            '9e506ee6e41db6b07f038e78664b435bfadd0b3a63fb275d611e161fba6ea230',
            bin2hex(current($reqs)->getIssuerKeyHash())
        );
        $this->assertEquals(
            '7f2b019daa51cd2bfd52f4dc66393929ed6372103e1371ca3c1fb0c1463b7fed',
            bin2hex(current($reqs)->getIssuerNameHash())
        );
        $this->assertEquals(
            '59772e700669b7669fb012c5cdd13c3a281a0911',
            current($reqs)->getSerialNumber()
        );
        $this->assertEquals(
            [
            'version' => 1,
            'requests' => [OCSPCommonTest::certId5977SHA256],
            'nonce' => 'cc51fed1358bcab2f2f345797a295d8d'
          ],
            $request->getAttributes()
        );
        $this->assertEquals(
            'e2ac8169783e498574836df97f7de700037c0cf2dc12cd30f9d55654bc04f3aa',
            bin2hex($request->getRequestIdentifier())
        );
        $this->assertEquals(
            [hex2bin('92fab49b04e6f07b7005ed6f79a9137bbfe8ad46a3ab216153ea0de6662d6e1d')],
            $request->getCertIdIdentifiers()
        );
    }

    public function testOCSPRequestFromCertificate()
    {
        $eucrtPEM = file_get_contents(
            __DIR__ . "/certs/" . self::eucrtfile
        );

        $eucrt = new X509Certificate(file_get_contents(__DIR__ . '/certs/' . self::eucrtfile));
        $qvcrt = new X509Certificate(file_get_contents(__DIR__ . '/certs/' . self::qvcrtfile));
        $eucrt->withIssuer($qvcrt);

        $req = OCSPRequest::fromCertificate(
            $eucrt,
            'sha256',
            'This is a Nonce!'
        );
        $this->assertEquals(
            [
                'version' => 1,
                'requests' => [OCSPCommonTest::certId5977SHA256],
                'nonce' => '546869732069732061204e6f6e636521'
            ],
            $req->getAttributes()
        );
        $this->assertEquals(
            'MIGXMIGUMG0wazBpMA0GCWCGSAFlAwQCAQUABCB/KwGdqlHNK/1S9NxmOTkp7WNy'.
            'ED4Tcco8H7DBRjt/7QQgnlBu5uQdtrB/A454ZktDW/rdCzpj+yddYR4WH7puojAC'.
            'FFl3LnAGabdmn7ASxc3RPDooGgkRoiMwITAfBgkrBgEFBQcwAQIEEgQQVGhpcyBp'.
            'cyBhIE5vbmNlIQ==',
            base64_encode($req->getBinary())
        );
    }

    public function testOCSPRequstFromMultipleCertificates()
    {
        $qvcrt = new X509Certificate(
            file_get_contents(__DIR__ . '/certs/' . self::qvcrtfile)
        );
        $itsmecrt = new X509Certificate(
            file_get_contents(__DIR__ . '/certs/' . self::itsmecrtfile)
        );
        $qventca1g3crt = new X509Certificate(
            file_get_contents(__DIR__ . '/certs/' . self::qventca1g3crtfile)
        );
        $qvcrt->withIssuer($qventca1g3crt);
        $itsmecrt->withIssuer($qventca1g3crt);
        $req = OCSPRequest::fromCertificate(
            [$qvcrt, $itsmecrt],
            'sha256',
            hex2bin('b7f18bd2f35428498546b23f80a227cc')
        );
        $this->assertEquals(
            base64_encode(file_get_contents(__DIR__.'/ocsp/request-multi2-qv-sha256')),
            base64_encode($req->getBinary())
        );
        $eucrt = new X509Certificate(
            file_get_contents(__DIR__ . '/certs/' . self::eucrtfile)
        );
        $eucrt->withIssuer($qvcrt);
        $req = OCSPRequest::fromCertificate(
            [$qvcrt, $itsmecrt, $eucrt],
            'sha256',
            hex2bin('b7f18bd2f35428498546b23f80a227cc')
        );
        $this->assertEquals(
            base64_encode(file_get_contents(__DIR__.'/ocsp/request-multi3-qv-sha256')),
            base64_encode($req->getBinary())
        );
        $this->assertEquals(
            [
              'requests' => [
                [
                  'serialNumber' => '40f6065343c04cb671e9c8250e90ebd58dd86e55',
                  'algorithmName' => 'sha-256',
                  'issuerKeyHash' => 'f3c0cc27a7f061e3553e38e7da96312002129437eb4a840f020fd84293d2663d',
                  'issuerNameHash' => '40e04b7b80abbdcf7641c3330bdd1d4f65aab4055e62c9aec0033e5d905f876e',
                  'signerIsIssuer' => 'unknown'
                ],
                [
                  'serialNumber' => '3b30442898d3be1cf55c5ea5ff04d6fb74701cd5',
                  'algorithmName' => 'sha-256',
                  'issuerKeyHash' => 'f3c0cc27a7f061e3553e38e7da96312002129437eb4a840f020fd84293d2663d',
                  'issuerNameHash' => '40e04b7b80abbdcf7641c3330bdd1d4f65aab4055e62c9aec0033e5d905f876e',
                  'signerIsIssuer' => 'unknown'
                ],
                OCSPCommonTest::certId5977SHA256
              ],
              'version' => 1,
              'nonce' => 'b7f18bd2f35428498546b23f80a227cc'
            ],
            $req->getAttributes()
        );
        $this->assertTrue($req->hasSubjects());
        $this->assertEquals(
            [
            'd90b40132306d1094608b1b9a2f6a9e23b45fe121fef514a1c9df70a815ad95c',
            'f640e5643c40c1f329e100438e28c957691afa8a53e405a326f7afeb70c23bc1',
            'ccd879b36bb553685becbd12901c7f41f7bd3e07f898fcbbe1eec456b03d7589'
          ],
            array_keys($req->getSubjects())
        );
    }
}
