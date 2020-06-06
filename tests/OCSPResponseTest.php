<?php

namespace eIDASCertificate\tests;

use PHPUnit\Framework\TestCase;
use eIDASCertificate\Certificate\X509Certificate;
use eIDASCertificate\OCSP\OCSPResponse;
use eIDASCertificate\OCSP\CertID;
use eIDASCertificate\OCSP\OCSPNonce;
use eIDASCertificate\OCSP\SingleResponse;
use eIDASCertificate\OCSP\ResponseData;
use eIDASCertificate\OCSP\CertStatus;
use eIDASCertificate\OCSP\BasicOCSPResponse;
use eIDASCertificate\Extension;
use eIDASCertificate\Algorithm\AlgorithmIdentifier;
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
        'revokedDateTime' => 1570480239,
        'thisUpdate' => 1591177149,
        'nextUpdate' => 1591779249
    ];

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
            'nonce' => 'cc51fed1358bcab2f2f345797a295d8d',
            'producerDN' => '/C=BM/O=QuoVadis Limited/OU=OCSP Responder/CN=QuoVadis OCSP Authority Signature'
          ],
            $responseData->getAttributes()
        );
        $this->assertEquals(
            '9b4e3bacbf144127bc583fb98db9c00d72a5da807f92843ce864aace0cf312a5',
            bin2hex($responseData->getHash('sha-256'))
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
            ],
            'producerKeyHash' => '0f80611c823161d52f28e78d4638b42ce1c6d9e2'
          ],
            $responseData->getAttributes()
        );
        $this->assertEquals(
            '37af9939d50817ceeca3d1f2d1235fae7634c904948a9d3100c69081dd69bf97',
            bin2hex($responseData->getHash('sha-256'))
        );
    }

    public function testBasicOCSPResponse()
    {
        $derWithoutCerts = base64_decode(
            'MIIByDCBsaIWBBQPgGEcgjFh1S8o541GOLQs4cbZ4hgPMjAyMDA2MDMwOTM5MDlaMIG'.
            'FMIGCMEkwCQYFKw4DAhoFAAQUEF+meoAInbUnnzXOgwtDiJ6jxw0EFA+AYRyCMWHVLy'.
            'jnjUY4tCzhxtniAhADcbWKhvbOnD7Le/Qvkgj8oREYDzIwMTkxMDA3MjAzMDM5WhgPM'.
            'jAyMDA2MDMwOTM5MDlaoBEYDzIwMjAwNjEwMDg1NDA5WjANBgkqhkiG9w0BAQsFAAOC'.
            'AQEAZc+SXtLysANqFBzzZi2M/Pki37bvDslS4Ofs1FUWbtganBA4iPI2USvAz6HL2LN'.
            'Zpgp8L6iYVlPa686bB37ZMoPZtTZD1xBLXdulCHDRG/Myif/wzdrhpU74iMV5/BN4h9'.
            'lRlXAoFRphTr87JyCJbhGtSQARA+nLEQ6AnQ9X+AdSQdHklg/2stL/MXp6XIXKlJJAO'.
            '7aqbwUYqxpVQet13uaqGrIxsChET56p6oKfZR+RO3jLF142laJhw5byNqXTSDAHez4N'.
            'yqx62BLezKbgjVsR5i5H1agY7iFHpOhPQjsbxJBqC5v35cAgNR+S85ia7H1xAyRbPn3'.
            'v66uWUW0bSg=='
        );
        $resp = BasicOCSPResponse::fromDER($derWithoutCerts);
        $this->assertEquals(
            base64_encode($derWithoutCerts),
            base64_encode($resp->getBinary())
        );
        $this->assertEquals(
            [
            'producedAt' => 1591177149,
            'responses' => [
              array_merge(
                  self::singleResponse371bRevoked,
                  self::certId371bSHA1
              )
            ],
            'signatureAlgorithm' => 'sha256WithRSAEncryption',
            'hasSignature' => true,
            'producerKeyHash' => '0f80611c823161d52f28e78d4638b42ce1c6d9e2'
          ],
            $resp->getAttributes()
        );
        $this->assertEquals(
            [
            '1.2.840.113549.1.1.11',
            'sha256WithRSAEncryption'
          ],
            [
            $resp->getSignatureAlgorithmOID(),
            $resp->getSignatureAlgorithmName()

          ]
        );
        $this->assertFalse(
            $resp->hasCertificates()
        );
        $this->assertEquals(
            'KeyHash',
            $resp->getResponderIDType()
        );
        $this->assertEquals(
            '0f80611c823161d52f28e78d4638b42ce1c6d9e2',
            $resp->getResponderIDPrintable()
        );
        $this->assertNull($resp->getSigningCert());
        $this->assertFalse(
            $resp->setResponder(
                file_get_contents(__DIR__.'/certs/qvbecag2.crt')
            )
        );
        $this->assertNull($resp->getSigningCert());
        $this->assertTrue(
            $resp->setResponder(
                file_get_contents(__DIR__.'/certs/DigiCertSHA2SecureServerCA.crt')
            )
        );
        $this->assertEquals(
            'eIDASCertificate\Certificate\X509Certificate',
            get_class($resp->getSigningCert())
        );
        $resp->setResponder(null);
        $this->assertNull(
            $resp->getSigningCert()
        );
        $derWithoutCertsTampered = base64_decode(
            str_replace('QEAZc+', 'QEA2Uo', base64_encode($derWithoutCerts))
        );
        $resp = BasicOCSPResponse::fromDER($derWithoutCertsTampered);
        $this->assertNull($resp->getSigningCert());
        $this->assertFalse(
            $resp->setResponder(
                file_get_contents(__DIR__.'/certs/qvbecag2.crt')
            )
        );
        $this->assertNull($resp->getSigningCert());
        $this->assertFalse(
            $resp->setResponder(
                file_get_contents(__DIR__.'/certs/DigiCertSHA2SecureServerCA.crt')
            )
        );

        $derWithCerts = base64_decode(
            'MIIHcTCCAT6hbzBtMQswCQYDVQQGEwJCTTEZMBcGA1UECgwQUXVvVmFkaXMgTGlta'.
            'XRlZDEXMBUGA1UECwwOT0NTUCBSZXNwb25kZXIxKjAoBgNVBAMMIVF1b1ZhZGlzIE'.
            '9DU1AgQXV0aG9yaXR5IFNpZ25hdHVyZRgPMjAyMDA1MzEyMDE1MDBaMIGUMIGRMGk'.
            'wDQYJYIZIAWUDBAIBBQAEIH8rAZ2qUc0r/VL03GY5OSntY3IQPhNxyjwfsMFGO3/t'.
            'BCCeUG7m5B22sH8DjnhmS0Nb+t0LOmP7J11hHhYfum6iMAIUWXcucAZpt2afsBLFz'.
            'dE8OigaCRGAABgPMjAyMDA1MzEyMDE1MDBaoBEYDzIwMjAwNjAyMjAxNTAwWqEjMC'.
            'EwHwYJKwYBBQUHMAECBBIEEMxR/tE1i8qy8vNFeXopXY0wDQYJKoZIhvcNAQELBQA'.
            'DggEBAHfUIkXtKrnKBgt2AgEgGrShuILxIQsoVHyEk3e8baPlWJQYxT6XhJh2uDds'.
            'zkx04C+uwmkjiGwUJNy3wYwHqsDReo3jhmxNC7zQXpQygl+yHydqxNGEWPVxEh6cf'.
            'jSHZp9PRaY9SUB0+bQzgNAc+Ygqpjcv7BJqvRSaq8NfUgJegdX2xhyscf3AlWcB8z'.
            'q3T5GGFS3QFDFNYD1V1N9lj24NGcRswCjer7kqVjUKjXktr3Hc93ygDVjaHTIQZTI'.
            'Q3Eg0B/9rLlJ3w17pmuZVtmJnpDBoJVHVEYrFXbC0YUUFSmGZef+f/6QdRen+6+6W'.
            'zaHxaMPMAwnl/1KfnkcLo7qgggUXMIIFEzCCBQ8wggL3oAMCAQICFBJY5QOKV/Lhi'.
            'YLZq+fBBPbPkLSHMA0GCSqGSIb3DQEBCwUAMHMxCzAJBgNVBAYTAkJFMRkwFwYDVQ'.
            'RhDBBOVFJCRS0wNTM3Njk4MzE4MSAwHgYDVQQKDBdRdW9WYWRpcyBUcnVzdGxpbms'.
            'gQlZCQTEnMCUGA1UEAwweUXVvVmFkaXMgQmVsZ2l1bSBJc3N1aW5nIENBIEcyMB4X'.
            'DTE5MTAxMTE0MzYyOVoXDTIyMTAxMTE0MzYyOVowbTELMAkGA1UEBhMCQk0xGTAXB'.
            'gNVBAoMEFF1b1ZhZGlzIExpbWl0ZWQxFzAVBgNVBAsMDk9DU1AgUmVzcG9uZGVyMS'.
            'owKAYDVQQDDCFRdW9WYWRpcyBPQ1NQIEF1dGhvcml0eSBTaWduYXR1cmUwggEiMA0'.
            'GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCrtwQVigkYNBrYpD4YGZgFNg3NV7ay'.
            'QhgKXA9k/+wvtotiIDfFPNB/5UdVxk+0r9GNwz3l7BW9D4rmeD+OuC4j71gzHkOaI'.
            'YfY95h5WCeCTvStmxUewaH9hvR61ANKqyom2W+xZzCxc97OFO52GqJpWvBuHhdhqU'.
            'ALMdGBeUxT7z5Qt7U+QUxfqKIxr9RxOvsx2Cu70xd/l3ouoSKegEj3kiI3t8QY3cC'.
            '3gWnTzGP+If25Mv5n7u7z9jVYuDUsPnpDnHtrXs0vl9aDBqAJgakzqNr1Q1WmbqTr'.
            'NrBSUb6c6ihCvUuhWvfJ8DIO6h+nkQepeILFAVTLJbsG7F9SAJfRAgMBAAGjgaAwg'.
            'Z0wDAYDVR0TAQH/BAIwADAfBgNVHSMEGDAWgBSHybwxlxJ6c7t+wD1FUbQBJZVRqz'.
            'AXBgNVHSAEEDAOMAwGCisGAQQBvlgBgiwwDwYJKwYBBQUHMAEFBAIFADATBgNVHSU'.
            'EDDAKBggrBgEFBQcDCTAdBgNVHQ4EFgQUt5B0c6liyvUNMI0jH1VrXgvH66YwDgYD'.
            'VR0PAQH/BAQDAgeAMA0GCSqGSIb3DQEBCwUAA4ICAQAxLisJUyYmjk5665KZM2zpY'.
            'BtesBb8EQ6yaUApXaYfeUzlXTqmCrzBUPsYFkfcFo1BNZNrtmngdHk4ZsU+MhgCxa'.
            '1NaQebQf53kfYI3ddO1Fl/Ao54zPHD8FHjCbGETr3dKg2MttgcORslyim0MFlucw0'.
            '7N3H/lu+rsWQcJAqWcn+2T6ZZ7Xek7byRW2gxrhbNeImbI1fcboujpUOJljgYub3W'.
            'U/2X0KLys62FOFgChsbPPtFNb1nECPCR4wKI33d2P3fjjZD52TVFk+fdamvJMc/oO'.
            'XceQEnCRivixdqBXf87IqXsnpv/9ySP7YOm/j/ASulqsCItZLVr1nu+UM1hlfmPTl'.
            'I9kFLztbsHUlWPaGGlP1A6cPU+yHcWG6iG7R/bXUjqltV9BSuyUGWRflb6qnLgCHL'.
            'sk17POiTfGF3TdieRI6R6LCalHeX9Zk86NxfvPLdS0igJycQgQ+tZ1aNaGrhbkfTq'.
            'Lr5dNt/2K4heOpgOBddECv/OtL3ZN48yU84DiaU1WqEmQA7vCFQOvw4IdkqpSIeDq'.
            'ukdM3sltuyayvxxHKCTqfvUTOW6mV91yndXAPgclkSmPrRZ91pcHo6Rull0U2CULx'.
            'M54+CupxmBiohZj1T1CiACCRGfT0bMeQLHj5T3VK3Yhtup8eZaMHYNCKbH6qxNErv'.
            'mUQ3kDJ9sjQ=='
        );
        $resp = BasicOCSPResponse::fromDER($derWithCerts);
        $this->assertEquals(
            base64_encode($derWithCerts),
            base64_encode($resp->getBinary())
        );
        $this->assertEquals(
            [
            'producedAt' => 1590956100,
            'responses' => [
              array_merge(
                  self::singleResponse5977Revoked,
                  self::certId5977SHA1
              )
            ],
            'signatureAlgorithm' => 'sha256WithRSAEncryption',
            'hasSignature' => true,
            'nonce' => 'cc51fed1358bcab2f2f345797a295d8d',
            'producerDN' => '/C=BM/O=QuoVadis Limited/OU=OCSP Responder/CN=QuoVadis OCSP Authority Signature',
            'signedByCert' => '2cce4d48cc716aaf0dfc87e096f03cf4c86c84cc20c1c11e3c18a58cd63b8f28'
          ],
            $resp->getAttributes()
        );
        $this->assertEquals(
            [
              '1.2.840.113549.1.1.11',
              'sha256WithRSAEncryption'
            ],
            [
              $resp->getSignatureAlgorithmOID(),
              $resp->getSignatureAlgorithmName()
            ]
        );
        $this->assertTrue(
            $resp->hasCertificates()
        );
        $this->assertEquals(
            1,
            sizeof($resp->getCertificates())
        );
        $this->assertEquals(
            '/C=BM/O=QuoVadis Limited/OU=OCSP Responder/CN=QuoVadis OCSP Authority Signature',
            $resp->getCertificates()[0]->getSubjectDN()
        );
        $this->assertEquals(
            '2cce4d48cc716aaf0dfc87e096f03cf4c86c84cc20c1c11e3c18a58cd63b8f28',
            hash('sha256', $resp->getCertificates()[0]->getBinary())
        );
        $this->assertEquals(
            'Name',
            $resp->getResponderIDType()
        );
        $this->assertEquals(
            '/C=BM/O=QuoVadis Limited/OU=OCSP Responder/CN=QuoVadis OCSP Authority Signature',
            $resp->getResponderIDPrintable()
        );
        $this->assertEquals(
            'eIDASCertificate\Certificate\X509Certificate',
            get_class($resp->getSigningCert())
        );
        $this->assertEquals(
            '/C=BM/O=QuoVadis Limited/OU=OCSP Responder/CN=QuoVadis OCSP Authority Signature',
            $resp->getSigningCert()->getSubjectDN()
        );
        $derWithCertsTampered = base64_decode(
            str_replace('ggEBAH', 'ggEBAJ', base64_encode($derWithCerts))
        );
        $resp = BasicOCSPResponse::fromDER($derWithCertsTampered);
        $this->assertEquals(
            '/C=BM/O=QuoVadis Limited/OU=OCSP Responder/CN=QuoVadis OCSP Authority Signature',
            $resp->getResponderIDPrintable()
        );
        $this->assertNull($resp->getSigningCert());
        $this->assertFalse(
            $resp->setResponder(
                file_get_contents(__DIR__.'/certs/qvbecag2.crt')
            )
        );
        $this->assertNull($resp->getSigningCert());
        $this->assertFalse(
            $resp->setResponder(
                file_get_contents(__DIR__.'/certs/DigiCertSHA2SecureServerCA.crt')
            )
        );
        $this->assertNull($resp->getSigningCert());
    }

    public function testOCSPResponse()
    {
        $resp = new OCSPResponse(6);
        $this->assertEquals(
            [
            'status' => 6,
            'statusReason' => 'Request unauthorized'
          ],
            $resp->getAttributes()
        );
        $derUnauthorized = base64_decode('MAMKAQY=');
        $this->assertEquals(
            base64_encode($derUnauthorized),
            base64_encode($resp->getBinary())
        );
        $this->assertNull(
            $resp->getSignatureAlgorithmOID()
        );
        $this->assertEquals(
            '',
            $resp->getSignatureAlgorithmName()
        );
        $resp = OCSPResponse::fromDER($derUnauthorized);
        $this->assertEquals(
            base64_encode($derUnauthorized),
            base64_encode($resp->getBinary())
        );
        $this->assertFalse($resp->hasSignature());
        $derEUGoodWithCerts = file_get_contents(__DIR__.'/ocsp/response-eucrt-sha1');
        $resp = OCSPResponse::fromDER($derEUGoodWithCerts);
        $this->assertEquals(
            base64_encode($derEUGoodWithCerts),
            base64_encode($resp->getBinary())
        );
        $this->assertEquals(
            [
            'status' => 0,
            'statusReason' => 'Response has valid confirmations',
            'producedAt' => 1591370661,
            'responses' => [
              [
                'serialNumber' => '59772e700669b7669fb012c5cdd13c3a281a0911',
                'algorithmName' => 'sha-1',
                'issuerKeyHash' => '87c9bc3197127a73bb7ec03d4551b401259551ab',
                'issuerNameHash' => 'c07b194b35d08214c0162e0d542ddd17f48b864b',
                'status' => 'good',
                'thisUpdate' => 1591370661,
                'nextUpdate' => 1591543461
              ]
            ],
            'nonce' => '1577e810f7379f0db3cef0e1abc6ebb7',
            'producerDN' => '/C=BM/O=QuoVadis Limited/OU=OCSP Responder/CN=QuoVadis OCSP Authority Signature',
            'signatureAlgorithm' => 'sha256WithRSAEncryption',
            'hasSignature' => true,
            'signedByCert' => '2cce4d48cc716aaf0dfc87e096f03cf4c86c84cc20c1c11e3c18a58cd63b8f28'
          ],
            $resp->getAttributes()
        );
        $derRevokedWithoutCerts = file_get_contents(__DIR__.'/ocsp/response-revoked-sha256');
        $this->assertEquals(
            '1.2.840.113549.1.1.11',
            $resp->getSignatureAlgorithmOID()
        );
        $this->assertEquals(
            'sha256WithRSAEncryption',
            $resp->getSignatureAlgorithmName()
        );
        $resp = OCSPResponse::fromDER($derRevokedWithoutCerts);
        $this->assertEquals(
            base64_encode($derRevokedWithoutCerts),
            base64_encode($resp->getBinary())
        );
        $this->assertTrue($resp->hasResponse());
        $this->assertEquals(
            '1.2.840.113549.1.1.11',
            $resp->getSignatureAlgorithmOID()
        );
        $this->assertEquals(
            'sha256WithRSAEncryption',
            $resp->getSignatureAlgorithmName()
        );
        $this->assertEquals(
            [
            'status' => 0,
            'statusReason' => 'Response has valid confirmations',
            'producedAt' => 1591177149,
            'responses' => [
              [
                'serialNumber' => '371b58a86f6ce9c3ecb7bf42f9208fc',
                'algorithmName' => 'sha-1',
                'issuerKeyHash' => '0f80611c823161d52f28e78d4638b42ce1c6d9e2',
                'issuerNameHash' => '105fa67a80089db5279f35ce830b43889ea3c70d',
                'status' => 'revoked',
                'thisUpdate' => 1591177149,
                'nextUpdate' => 1591779249,
                'revokedDateTime' => 1570480239
              ]
            ],
            'producerKeyHash' => '0f80611c823161d52f28e78d4638b42ce1c6d9e2',
            'signatureAlgorithm' => 'sha256WithRSAEncryption',
            'hasSignature' => true
            ],
            $resp->getAttributes()
        );
        $this->assertNull($resp->getSigningCert());
        $this->assertFalse(
            $resp->setResponder(
                file_get_contents(__DIR__.'/certs/qvbecag2.crt')
            )
        );
        $this->assertNull($resp->getSigningCert());
        $this->assertTrue(
            $resp->setResponder(
                file_get_contents(__DIR__.'/certs/DigiCertSHA2SecureServerCA.crt')
            )
        );
        $this->assertEquals(
            'eIDASCertificate\Certificate\X509Certificate',
            get_class($resp->getSigningCert())
        );
        $this->assertFalse(
            $resp->hasCertificates()
        );
        $this->assertEquals(
            '/C=US/O=DigiCert Inc/CN=DigiCert SHA2 Secure Server CA',
            $resp->getSigningCert()->getSubjectDN()
        );
    }
}
