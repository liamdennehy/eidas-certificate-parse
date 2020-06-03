<?php

namespace eIDASCertificate\tests;

use PHPUnit\Framework\TestCase;
use eIDASCertificate\OCSP\OCSPResponse;
use eIDASCertificate\OCSP\CertID;
use eIDASCertificate\OCSP\OCSPNonce;
use eIDASCertificate\OCSP\SingleResponse;
use eIDASCertificate\OCSP\CertStatus;
use eIDASCertificate\Extension;
use eIDASCertificate\AlgorithmIdentifier;
use ASN1\Type\UnspecifiedType;
use DateTime;

class OCSPResponseTest extends TestCase
{
    // public function testOCSPResponse($value='')
    // {
    //     $seq = OCSPResponse::fromDER(file_get_contents(__DIR__.'/ocsp/response-sha256'));
    // }

    public function testCertStatus()
    {
        $goodDER = base64_decode('gAA=');
        $revokedDER = base64_decode('oREYDzIwMTkxMDA3MjAzMDM5Wg===');
        $good = CertStatus::fromDER($goodDER);
        $this->assertEquals(
            'good',
            $good->getStatus()
        );
        $this->assertEquals(
            [
            'status' => 'good'
          ],
            $good->getAttributes()
        );
        $this->assertEquals(
            base64_encode($goodDER),
            base64_encode($good->getBinary())
        );
        $good = new CertStatus('good');
        $this->assertEquals(
            [
            'status' => 'good'
          ],
            $good->getAttributes()
        );
        $revoked = CertStatus::fromDER($revokedDER);
        $this->assertEquals(
            'revoked',
            $revoked->getStatus()
        );
        $this->assertEquals(
            '1570480239',
            $revoked->getRevokedDateTime()->format('U')
        );
        $this->assertEquals(
            [
            'status' => 'revoked',
            'revokedDateTime' => '1570480239'
          ],
            $revoked->getAttributes()
        );
        $this->assertEquals(
            base64_encode($revokedDER),
            base64_encode($revoked->getBinary())
        );
        $good = new CertStatus('revoked', new DateTime('2019-10-07 20:30:39'));
        $this->assertEquals(
            [
            'status' => 'revoked',
            'revokedDateTime' => '1570480239'
          ],
            $revoked->getAttributes()
        );
        $this->assertEquals(
            base64_encode($revokedDER),
            base64_encode($revoked->getBinary())
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
            [
                'serialNumber' => '371b58a86f6ce9c3ecb7bf42f9208fc',
                'algorithmName' => 'sha-1',
                'issuerKeyHash' => '0f80611c823161d52f28e78d4638b42ce1c6d9e2',
                'issuerNameHash' => '105fa67a80089db5279f35ce830b43889ea3c70d',
            ],
            $certId->getAttributes()
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
        $certId = new CertID(
            'sha-1',
            hex2bin('105fa67a80089db5279f35ce830b43889ea3c70d'),
            hex2bin('0f80611c823161d52f28e78d4638b42ce1c6d9e2'),
            '371b58a86f6ce9c3ecb7bf42f9208fc'
        );
        $this->assertEquals(
            [
                'serialNumber' => '371b58a86f6ce9c3ecb7bf42f9208fc',
                'algorithmName' => 'sha-1',
                'issuerKeyHash' => '0f80611c823161d52f28e78d4638b42ce1c6d9e2',
                'issuerNameHash' => '105fa67a80089db5279f35ce830b43889ea3c70d',
            ],
            $certId->getAttributes()
        );
        $this->assertEquals(
            base64_encode($derSHA1),
            base64_encode($certId->getBinary())
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
            [
              'serialNumber' => '59772e700669b7669fb012c5cdd13c3a281a0911',
              'algorithmName' => 'sha-256',
              'issuerKeyHash' => '9e506ee6e41db6b07f038e78664b435bfadd0b3a63fb275d611e161fba6ea230',
              'issuerNameHash' => '7f2b019daa51cd2bfd52f4dc66393929ed6372103e1371ca3c1fb0c1463b7fed',
            ],
            $certId->getAttributes()
        );
        $this->assertEquals(
            base64_encode($derSHA256),
            base64_encode($certId->getBinary())
        );
        $certId = new CertID(
            'sha-256',
            hex2bin('7f2b019daa51cd2bfd52f4dc66393929ed6372103e1371ca3c1fb0c1463b7fed'),
            hex2bin('9e506ee6e41db6b07f038e78664b435bfadd0b3a63fb275d611e161fba6ea230'),
            '59772e700669b7669fb012c5cdd13c3a281a0911'
        );
        $this->assertEquals(
            [
              'serialNumber' => '59772e700669b7669fb012c5cdd13c3a281a0911',
              'algorithmName' => 'sha-256',
              'issuerKeyHash' => '9e506ee6e41db6b07f038e78664b435bfadd0b3a63fb275d611e161fba6ea230',
              'issuerNameHash' => '7f2b019daa51cd2bfd52f4dc66393929ed6372103e1371ca3c1fb0c1463b7fed',
            ],
            $certId->getAttributes()
        );
        $this->assertEquals(
            base64_encode($derSHA256),
            base64_encode($certId->getBinary())
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

    public function testSingleResponseRevoked($value='')
    {
        $derRevoked = base64_decode(
            'MIGCMEkwCQYFKw4DAhoFAAQUEF+meoAInbUnnzXOgwtDiJ6jxw0EFA+AYRyCMWH'.
            'VLyjnjUY4tCzhxtniAhADcbWKhvbOnD7Le/Qvkgj8oREYDzIwMTkxMDA3MjAzMD'.
            'M5WhgPMjAyMDA2MDMwOTM5MDlaoBEYDzIwMjAwNjEwMDg1NDA5Wg=='
        );
        $sResp = SingleResponse::fromDER($derRevoked);

        $this->assertEquals(
            base64_encode($derRevoked),
            base64_encode($sResp->getBinary())
        );
        $this->assertEquals(
            [
                'serialNumber' => '371b58a86f6ce9c3ecb7bf42f9208fc',
                'algorithmName' => 'sha-1',
                'issuerKeyHash' => '0f80611c823161d52f28e78d4638b42ce1c6d9e2',
                'issuerNameHash' => '105fa67a80089db5279f35ce830b43889ea3c70d',
                'status' => 'revoked',
                'revokedDateTime' => '1570480239',
                'thisUpdate' => '1591177149',
                'nextUpdate' => '1591779249'
            ],
            $sResp->getAttributes()
        );
    }

    public function testSingleResponse($value='')
    {
        $der = base64_decode(
            'MIGRMGkwDQYJYIZIAWUDBAIBBQAEIH8rAZ2qUc0r/VL03GY5OSntY3IQPhNxyjwfsMF'.
            'GO3/tBCCeUG7m5B22sH8DjnhmS0Nb+t0LOmP7J11hHhYfum6iMAIUWXcucAZpt2afsB'.
            'LFzdE8OigaCRGAABgPMjAyMDA1MzEyMDE1MDBaoBEYDzIwMjAwNjAyMjAxNTAwWg=='
        );
        $sResp = SingleResponse::fromDER($der);

        $this->assertEquals(
            base64_encode($der),
            base64_encode($sResp->getBinary())
        );
        $this->assertEquals(
            [
              'serialNumber' => '59772e700669b7669fb012c5cdd13c3a281a0911',
              'algorithmName' => 'sha-256',
              'issuerKeyHash' => '9e506ee6e41db6b07f038e78664b435bfadd0b3a63fb275d611e161fba6ea230',
              'issuerNameHash' => '7f2b019daa51cd2bfd52f4dc66393929ed6372103e1371ca3c1fb0c1463b7fed',
              'status' => 'good',
              'thisUpdate' => '1590956100',
              'nextUpdate' => '1591128900'
            ],
            $sResp->getAttributes()
        );
    }
}
