<?php

namespace eIDASCertificate\tests;

use PHPUnit\Framework\TestCase;
use eIDASCertificate\OCSP\OCSPResponse;
use eIDASCertificate\OCSP\CertID;
use eIDASCertificate\OCSP\OCSPNonce;
use eIDASCertificate\OCSP\SingleResponse;
use eIDASCertificate\OCSP\ResponseData;
use eIDASCertificate\OCSP\CertStatus;
use eIDASCertificate\Extension;
use eIDASCertificate\AlgorithmIdentifier;
use ASN1\Type\UnspecifiedType;
use DateTime;

class OCSPResponseTest extends TestCase
{
    const certId371bSHA1 = [
        'serialNumber' => '371b58a86f6ce9c3ecb7bf42f9208fc',
        'algorithmName' => 'sha-1',
        'issuerKeyHash' => '0f80611c823161d52f28e78d4638b42ce1c6d9e2',
        'issuerNameHash' => '105fa67a80089db5279f35ce830b43889ea3c70d',
    ];
    const certId5977SHA1 = [
        'serialNumber' => '59772e700669b7669fb012c5cdd13c3a281a0911',
        'algorithmName' => 'sha-256',
        'issuerKeyHash' => '9e506ee6e41db6b07f038e78664b435bfadd0b3a63fb275d611e161fba6ea230',
        'issuerNameHash' => '7f2b019daa51cd2bfd52f4dc66393929ed6372103e1371ca3c1fb0c1463b7fed',
    ];
    const singleResponse5977Revoked = [
      'status' => 'good',
      'thisUpdate' => '1590956100',
      'nextUpdate' => '1591128900'
    ];
    const singleResponse371bRevoked = [
        'status' => 'revoked',
        'revokedDateTime' => '1570480239',
        'thisUpdate' => '1591177149',
        'nextUpdate' => '1591779249'
    ];
    public function testOCSPResponse($value='')
    {
        $der = file_get_contents(__DIR__.'/ocsp/revoked-response-sha256');
        $seq = OCSPResponse::fromDER($der);
    }

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
            self::certId371bSHA1,
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
            self::certId371bSHA1,
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
            self::certId5977SHA1,
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
            self::certId5977SHA1,
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
            array_merge(self::certId371bSHA1, self::singleResponse371bRevoked),
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
            array_merge(self::certId5977SHA1, self::singleResponse5977Revoked),
            $sResp->getAttributes()
        );
    }

    public function testResponseData()
    {
        // DN identifier, cert is good
        $derDNGood = base64_decode(
            'MIIBPqFvMG0xCzAJBgNVBAYTAkJNMRkwFwYDVQQKDBBRdW9WYWRpcyBMaW1pdGVkM'.
            'RcwFQYDVQQLDA5PQ1NQIFJlc3BvbmRlcjEqMCgGA1UEAwwhUXVvVmFkaXMgT0NTUC'.
            'BBdXRob3JpdHkgU2lnbmF0dXJlGA8yMDIwMDUzMTIwMTUwMFowgZQwgZEwaTANBgl'.
            'ghkgBZQMEAgEFAAQgfysBnapRzSv9UvTcZjk5Ke1jchA+E3HKPB+wwUY7f+0EIJ5Q'.
            'bubkHbawfwOOeGZLQ1v63Qs6Y/snXWEeFh+6bqIwAhRZdy5wBmm3Zp+wEsXN0Tw6K'.
            'BoJEYAAGA8yMDIwMDUzMTIwMTUwMFqgERgPMjAyMDA2MDIyMDE1MDBaoSMwITAfBg'.
            'krBgEFBQcwAQIEEgQQzFH+0TWLyrLy80V5eildjQ=='
        );
        $responseData = ResponseData::fromDER($derDNGood);
        $this->assertEquals(
            base64_encode($derDNGood),
            base64_encode($responseData->getBinary())
        );
        $this->assertEquals(
            [
              'producedAt' => 1590956100,
              'responses' => [
              array_merge(self::certId5977SHA1, self::singleResponse5977Revoked)
            ],
            'nonce' => 'cc51fed1358bcab2f2f345797a295d8d'
          ],
            $responseData->getAttributes()
        );

        // KeyHash identifier, cert is revoked
        $derKHRevoked = base64_decode(
            'MIGxohYEFA+AYRyCMWHVLyjnjUY4tCzhxtniGA8yMDIwMDYwMzA5MzkwOVowgYUwg'.
            'YIwSTAJBgUrDgMCGgUABBQQX6Z6gAidtSefNc6DC0OInqPHDQQUD4BhHIIxYdUvKO'.
            'eNRji0LOHG2eICEANxtYqG9s6cPst79C+SCPyhERgPMjAxOTEwMDcyMDMwMzlaGA8'.
            'yMDIwMDYwMzA5MzkwOVqgERgPMjAyMDA2MTAwODU0MDla'
        );
        $responseData = ResponseData::fromDER($derKHRevoked);
        $this->assertEquals(
            base64_encode($derKHRevoked),
            base64_encode($responseData->getBinary())
        );
        $this->assertEquals(
            [
              'producedAt' => 1591177149,
              'responses' => [
              array_merge(self::certId371bSHA1, self::singleResponse371bRevoked)
            ]
          ],
            $responseData->getAttributes()
        );
    }
}
