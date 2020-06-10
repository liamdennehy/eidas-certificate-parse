<?php

namespace eIDASCertificate\tests;

use PHPUnit\Framework\TestCase;
use eIDASCertificate\Algorithm\AlgorithmIdentifier;
use eIDASCertificate\Certificate\X509Certificate;
use eIDASCertificate\OCSP\OCSPRequest;
use eIDASCertificate\OCSP\CertID;
use eIDASCertificate\OCSP\Request;
use eIDASCertificate\OCSP\TBSRequest;
use eIDASCertificate\OCSP\OCSPNonce;
use eIDASCertificate\Extension;
use ASN1\Type\UnspecifiedType;

class OCSPCommonTest extends TestCase
{
    private $requestDER;

    const eucrtfile = 'European-Commission.crt';
    const qvcrtfile = 'qvbecag2.crt';
    // const eucrtReqAttributes = [
    //   'serialNumber' => '59772e700669b7669fb012c5cdd13c3a281a0911',
    //   'algorithmName' => 'sha-256',
    //   'issuerKeyHash' => '9e506ee6e41db6b07f038e78664b435bfadd0b3a63fb275d611e161fba6ea230',
    //   'issuerNameHash' => '7f2b019daa51cd2bfd52f4dc66393929ed6372103e1371ca3c1fb0c1463b7fed',
    //   'signerIsIssuer' => 'unknown'
    // ];
    const certId371bSHA1 = [
        'serialNumber' => '371b58a86f6ce9c3ecb7bf42f9208fc',
        'algorithmName' => 'sha-1',
        'issuerKeyHash' => '0f80611c823161d52f28e78d4638b42ce1c6d9e2',
        'issuerNameHash' => '105fa67a80089db5279f35ce830b43889ea3c70d',
        'signerIsIssuer' => 'unknown'
    ];
    const certId5977SHA256 = [
        'serialNumber' => '59772e700669b7669fb012c5cdd13c3a281a0911',
        'algorithmName' => 'sha-256',
        'issuerKeyHash' => '9e506ee6e41db6b07f038e78664b435bfadd0b3a63fb275d611e161fba6ea230',
        'issuerNameHash' => '7f2b019daa51cd2bfd52f4dc66393929ed6372103e1371ca3c1fb0c1463b7fed',
        'signerIsIssuer' => 'unknown'
    ];
    const certId5977SHA1 = [
      'serialNumber' => '59772e700669b7669fb012c5cdd13c3a281a0911',
      'algorithmName' => 'sha-1',
      'issuerKeyHash' => '87c9bc3197127a73bb7ec03d4551b401259551ab',
      'issuerNameHash' => 'c07b194b35d08214c0162e0d542ddd17f48b864b',
      'signerIsIssuer' => 'unknown'
    ];
    const certIda85dSHA1 = [
      'serialNumber' => 'a85d4c6820beff673073658e163c2f9d',
      'algorithmName' => 'sha-1',
      'issuerKeyHash' => '82af6c8cf8c5fe96617ce81f3d2b71485ec48bc0',
      'issuerNameHash' => 'c4c3dd52a50e02dd3c949825b7295ad3aec64b3e',
      'signerIsIssuer' => 'unknown'
    ];

    public function setUp()
    {
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

    public function testCertID()
    {
        $sha1 = new AlgorithmIdentifier('sha1');
        $sha256 = new AlgorithmIdentifier('sha256');
        $derSHA1 = base64_decode(
            'MEkwCQYFKw4DAhoFAAQUEF+meoAInbUnnzXOgwtDiJ6jxw0EFA+AYRyCMWHVLyjn'.
            'jUY4tCzhxtniAhADcbWKhvbOnD7Le/Qvkgj8'
        );
        $certId = CertID::fromDER($derSHA1);
        $this->assertEquals(
            self::certId371bSHA1,
            $certId->getAttributes()
        );
        $this->assertEquals(
            base64_encode($derSHA1),
            base64_encode($certId->getBinary())
        );
        // $derSHA256 = base64_decode(
        //     'MGkwDQYJYIZIAWUDBAIBBQAEIH8rAZ2qUc0r/VL03GY5OSntY3IQPhNxyjwfsMF'.
        //     'GO3/tBCCeUG7m5B22sH8DjnhmS0Nb+t0LOmP7J11hHhYfum6iMAIUWXcucAZpt2'.
        //     'afsBLFzdE8OigaCRE='
        // );
        $this->assertEquals(
            'c049df4808ccb6d8875d2816d6214f21eb781f051ab2e1a05c7f16bf7338e04f',
            bin2hex($certId->getIdentifier())
        );
        $certId = new CertID(
            'sha-1',
            hex2bin('105fa67a80089db5279f35ce830b43889ea3c70d'),
            hex2bin('0f80611c823161d52f28e78d4638b42ce1c6d9e2'),
            '371b58a86f6ce9c3ecb7bf42f9208fc'
        );
        $this->assertEquals(
            self::certId371bSHA1,
            $certId->getAttributes()
        );
        $this->assertEquals(
            base64_encode($derSHA1),
            base64_encode($certId->getBinary())
        );
        $this->assertEquals(
            'c049df4808ccb6d8875d2816d6214f21eb781f051ab2e1a05c7f16bf7338e04f',
            bin2hex($certId->getIdentifier())
        );

        $certId = new CertID(
            $sha1,
            hex2bin('105fa67a80089db5279f35ce830b43889ea3c70d'),
            hex2bin('0f80611c823161d52f28e78d4638b42ce1c6d9e2'),
            '371b58a86f6ce9c3ecb7bf42f9208fc'
        );
        $this->assertEquals(
            base64_encode($derSHA1),
            base64_encode($certId->getBinary())
        );
        $derSHA256 = base64_decode(
            'MGkwDQYJYIZIAWUDBAIBBQAEIH8rAZ2qUc0r/VL03GY5OSntY3IQPhNxyjwfsMF'.
            'GO3/tBCCeUG7m5B22sH8DjnhmS0Nb+t0LOmP7J11hHhYfum6iMAIUWXcucAZpt2'.
            'afsBLFzdE8OigaCRE='
        );
        $certId = CertID::fromDER($derSHA256);
        $this->assertEquals(
            self::certId5977SHA256,
            $certId->getAttributes()
        );
        $this->assertEquals(
            base64_encode($derSHA256),
            base64_encode($certId->getBinary())
        );
        $this->assertEquals(
            '92fab49b04e6f07b7005ed6f79a9137bbfe8ad46a3ab216153ea0de6662d6e1d',
            bin2hex($certId->getIdentifier())
        );
        $certId = new CertID(
            'sha-256',
            hex2bin('7f2b019daa51cd2bfd52f4dc66393929ed6372103e1371ca3c1fb0c1463b7fed'),
            hex2bin('9e506ee6e41db6b07f038e78664b435bfadd0b3a63fb275d611e161fba6ea230'),
            '59772e700669b7669fb012c5cdd13c3a281a0911'
        );
        $this->assertEquals(
            self::certId5977SHA256,
            $certId->getAttributes()
        );
        $this->assertEquals(
            base64_encode($derSHA256),
            base64_encode($certId->getBinary())
        );
        $this->assertEquals(
            '92fab49b04e6f07b7005ed6f79a9137bbfe8ad46a3ab216153ea0de6662d6e1d',
            bin2hex($certId->getIdentifier())
        );
        $certId = new CertID(
            $sha256,
            hex2bin('7f2b019daa51cd2bfd52f4dc66393929ed6372103e1371ca3c1fb0c1463b7fed'),
            hex2bin('9e506ee6e41db6b07f038e78664b435bfadd0b3a63fb275d611e161fba6ea230'),
            '59772e700669b7669fb012c5cdd13c3a281a0911'
        );
        $this->assertEquals(
            base64_encode($derSHA256),
            base64_encode($certId->getBinary())
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
            self::certIda85dSHA1,
            $certId->getAttributes()
        );
        $this->assertEquals(
            '39c0f4d655b00d944a23187174a5f7c7b5b356b4f4c3981e8c86fec744e69a42',
            bin2hex($certId->getIdentifier())
        );
    }

    public function testCertIdMore()
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
        $this->assertEquals(
            '39c0f4d655b00d944a23187174a5f7c7b5b356b4f4c3981e8c86fec744e69a42',
            bin2hex($newCertId->getIdentifier())
        );
    }

    public function testCertIDFromCertificate()
    {
        $eucrt = new X509Certificate(
            file_get_contents(__DIR__.'/certs/'.self::eucrtfile)
        );
        $this->assertNull(
            $eucrt->getCertId()
        );
        $eucrt->withIssuer(new X509Certificate(
            file_get_contents(__DIR__.'/certs/'.self::qvcrtfile)
        ));

        $certId = $eucrt->getCertId();
        $this->assertEquals(
            '92fab49b04e6f07b7005ed6f79a9137bbfe8ad46a3ab216153ea0de6662d6e1d',
            bin2hex($certId->getIdentifier())
        );
        $this->assertEquals(
            self::certId5977SHA256,
            $certId->getAttributes()
        );

        $certId = $eucrt->getCertId('sha256');
        $this->assertEquals(
            '92fab49b04e6f07b7005ed6f79a9137bbfe8ad46a3ab216153ea0de6662d6e1d',
            bin2hex($certId->getIdentifier())
        );
        $this->assertEquals(
            self::certId5977SHA256,
            $certId->getAttributes()
        );

        $certId = $eucrt->getCertId('sha1');
        $this->assertEquals(
            'e8f357e7ecbac7e87b3939045093f52913bc2356921ad431181627c1e2287882',
            bin2hex($certId->getIdentifier())
        );
        $this->assertEquals(
            self::certId5977SHA1,
            $certId->getAttributes()
        );
    }
}
