<?php

namespace eIDASCertificate\tests;

use PHPUnit\Framework\TestCase;
use eIDASCertificate\Extension;
use eIDASCertificate\Extensions;
use eIDASCertificate\Certificate\AuthorityInformationAccess;
use eIDASCertificate\Certificate\AuthorityKeyIdentifier;
use eIDASCertificate\Certificate\CertificatePolicies;
use eIDASCertificate\Certificate\SubjectKeyIdentifier;
use eIDASCertificate\Certificate\BasicConstraints;
use eIDASCertificate\Certificate\CRLDistributionPoints;
use eIDASCertificate\Certificate\ExtendedKeyUsage;
use eIDASCertificate\Certificate\KeyUsage;
use eIDASCertificate\Certificate\OCSPNoCheck;
use eIDASCertificate\Certificate\PreCertPoison;
use eIDASCertificate\Certificate\SCTList;
use eIDASCertificate\Certificate\SubjectAltName;
use ASN1\Type\UnspecifiedType;

class ExtensionTest extends TestCase
{
    public function testExtensions()
    {
        $extensionsDER = base64_decode(
            "MIIFFDAOBgNVHQ8BAf8EBAMCBaAwEwYKKwYBBAHWeQIEAwEB/wQCBQAwHQYDVR0lBBY".
            "wFAYIKwYBBQUHAwEGCCsGAQUFBwMCMIIBXQYDVR0gBIIBVDCCAVAwggE3Bg8rBgEEAY".
            "GoGAIBAYEqAgkwggEiMCYGCCsGAQUFBwIBFhpodHRwOi8vY3AuZS1zemlnbm8uaHUvc".
            "WNwczBEBggrBgEFBQcCAjA4DDZRdWFsaWZpZWQgUFNEMiBjZXJ0aWZpY2F0ZSBmb3Ig".
            "d2Vic2l0ZSBhdXRoZW50aWNhdGlvbi4wNAYIKwYBBQUHAgIwKAwmT3JnYW5pemF0aW9".
            "uYWwgdmFsaWRhdGlvbiBjZXJ0aWZpY2F0ZS4wRQYIKwYBBQUHAgIwOQw3TWluxZFzw6".
            "10ZXR0IFBTRDIgd2Vib2xkYWwtaGl0ZWxlc8OtdMWRIHRhbsO6c8OtdHbDoW55LjA1B".
            "ggrBgEFBQcCAjApDCdTemVydmV6ZXQtZWxsZW7FkXJ6w7Z0dCB0YW7DunPDrXR2w6Fu".
            "eS4wCQYHBACBmCcDATAIBgZngQwBAgIwHQYDVR0OBBYEFCI7XaCk9Uctd6iTKpvkp0m".
            "19TRqMB8GA1UdIwQYMBaAFH2ETsLUa+rB1yKMaMPpoPTsmIocMCgGA1UdEQQhMB+CHX".
            "BzZDJodWIucXdhYy5jbGllbnQuYXBpLmtoLmh1MIG2BgNVHR8Ega4wgaswN6A1oDOGM".
            "Wh0dHA6Ly9xdGxzY2EyMDE4LWNybDEuZS1zemlnbm8uaHUvcXRsc2NhMjAxOC5jcmww".
            "N6A1oDOGMWh0dHA6Ly9xdGxzY2EyMDE4LWNybDIuZS1zemlnbm8uaHUvcXRsc2NhMjA".
            "xOC5jcmwwN6A1oDOGMWh0dHA6Ly9xdGxzY2EyMDE4LWNybDMuZS1zemlnbm8uaHUvcX".
            "Rsc2NhMjAxOC5jcmwwggFfBggrBgEFBQcBAQSCAVEwggFNMC8GCCsGAQUFBzABhiNod".
            "HRwOi8vcXRsc2NhMjAxOC1vY3NwMS5lLXN6aWduby5odTAvBggrBgEFBQcwAYYjaHR0".
            "cDovL3F0bHNjYTIwMTgtb2NzcDIuZS1zemlnbm8uaHUwLwYIKwYBBQUHMAGGI2h0dHA".
            "6Ly9xdGxzY2EyMDE4LW9jc3AzLmUtc3ppZ25vLmh1MDwGCCsGAQUFBzAChjBodHRwOi".
            "8vcXRsc2NhMjAxOC1jYTEuZS1zemlnbm8uaHUvcXRsc2NhMjAxOC5jcnQwPAYIKwYBB".
            "QUHMAKGMGh0dHA6Ly9xdGxzY2EyMDE4LWNhMi5lLXN6aWduby5odS9xdGxzY2EyMDE4".
            "LmNydDA8BggrBgEFBQcwAoYwaHR0cDovL3F0bHNjYTIwMTgtY2EzLmUtc3ppZ25vLmh".
            "1L3F0bHNjYTIwMTguY3J0MIHmBggrBgEFBQcBAwSB2TCB1jAIBgYEAI5GAQEwCwYGBA".
            "CORgEDAgEKMFMGBgQAjkYBBTBJMCQWHmh0dHBzOi8vY3AuZS1zemlnbm8uaHUvcWNwc".
            "19lbhMCRU4wIRYbaHR0cHM6Ly9jcC5lLXN6aWduby5odS9xY3BzEwJIVTATBgYEAI5G".
            "AQYwCQYHBACORgEGAzBTBgYEAIGYJwIwSTAmMBEGBwQAgZgnAQIMBlBTUF9QSTARBgc".
            "EAIGYJwEDDAZQU1BfQUkMF0NlbnRyYWwgQmFuayBvZiBIdW5nYXJ5DAZIVS1DQkg="
        );
        $extensions = new Extensions(
            UnspecifiedType::fromDER($extensionsDER)->asSequence()
        );
        $this->assertEquals(
            base64_encode($extensionsDER),
            base64_encode($extensions->getBinary())
        );
        $this->assertEquals(
            [
              'keyUsage',
              'preCertPoison',
              'extKeyUsage',
              'certificatePolicies',
              'subjectKeyIdentifier',
              'authorityKeyIdentifier',
              'subjectAltName',
              'crlDistributionPoints',
              'authorityInfoAccess',
              'qcStatements'
            ],
            array_keys($extensions->getExtensions())
        );
    }

    public function testCRLDistributionPoints()
    {
        $binary = base64_decode('MIGrMDegNaAzhjFodHRwOi8vcXRsc2NhMjAxOC1jcmwxL'.
        'mUtc3ppZ25vLmh1L3F0bHNjYTIwMTguY3JsMDegNaAzhjFodHRwOi8vcXRsc2NhMjAxOC'.
        '1jcmwyLmUtc3ppZ25vLmh1L3F0bHNjYTIwMTguY3JsMDegNaAzhjFodHRwOi8vcXRsc2N'.
        'hMjAxOC1jcmwzLmUtc3ppZ25vLmh1L3F0bHNjYTIwMTguY3Js');
        $extnCDPs = new CRLDistributionPoints($binary);
        $this->assertEquals(
            [
              'http://qtlsca2018-crl1.e-szigno.hu/qtlsca2018.crl',
              'http://qtlsca2018-crl2.e-szigno.hu/qtlsca2018.crl',
              'http://qtlsca2018-crl3.e-szigno.hu/qtlsca2018.crl'
            ],
            $extnCDPs->getCDPs()
        );
    }

    public function testKeyUsage()
    {
        $binary = base64_decode('AwIBBg==');
        $keyUsage = new KeyUsage($binary);
        $this->assertEquals(
            [
              'digitalSignature' => false,
              'nonRepudiation' => false,
              'keyEncipherment' => false,
              'dataEncipherment' => false,
              'keyAgreement' => false,
              'keyCertSign' => true,
              'cRLSign' => true,
              'encipherOnly' => false,
              'decipherOnly' => false
            ],
            $keyUsage->getKeyUsage()
        );
        $binary = base64_decode('AwIFoA==');
        $keyUsage = new KeyUsage($binary);
        $this->assertEquals(
            [
              'digitalSignature' => true,
              'nonRepudiation' => false,
              'keyEncipherment' => true,
              'dataEncipherment' => false,
              'keyAgreement' => false,
              'keyCertSign' => false,
              'cRLSign' => false,
              'encipherOnly' => false,
              'decipherOnly' => false
            ],
            $keyUsage->getKeyUsage()
        );
        $binary = base64_decode('AwIEMA==');
        $keyUsage = new KeyUsage($binary);
        $this->assertEquals(
            [
              'digitalSignature' => false,
              'nonRepudiation' => false,
              'keyEncipherment' => true,
              'dataEncipherment' => true,
              'keyAgreement' => false,
              'keyCertSign' => false,
              'cRLSign' => false,
              'encipherOnly' => false,
              'decipherOnly' => false
            ],
            $keyUsage->getKeyUsage()
        );
    }

    public function testAKI()
    {
        $binary = base64_decode('MBaAFH2ETsLUa+rB1yKMaMPpoPTsmIoc');
        $aki = new AuthorityKeyIdentifier($binary);
        $this->assertEquals(
            '7d844ec2d46beac1d7228c68c3e9a0f4ec988a1c',
            bin2hex($aki->getKeyId())
        );
    }

    public function testSKI()
    {
        $binary = base64_decode('BBQiO12gpPVHLXeokyqb5KdJtfU0ag==');
        $aki = new SubjectKeyIdentifier($binary);
        $this->assertEquals(
            '223b5da0a4f5472d77a8932a9be4a749b5f5346a',
            bin2hex($aki->getKeyId())
        );
    }

    public function testAIA()
    {
        $binary = base64_decode(
            'MIIBTTAvBggrBgEFBQcwAYYjaHR0cDovL3F0bHNjYTIwMTgtb2NzcDEuZS1zemln'.
            'bm8uaHUwLwYIKwYBBQUHMAGGI2h0dHA6Ly9xdGxzY2EyMDE4LW9jc3AyLmUtc3pp'.
            'Z25vLmh1MC8GCCsGAQUFBzABhiNodHRwOi8vcXRsc2NhMjAxOC1vY3NwMy5lLXN6'.
            'aWduby5odTA8BggrBgEFBQcwAoYwaHR0cDovL3F0bHNjYTIwMTgtY2ExLmUtc3pp'.
            'Z25vLmh1L3F0bHNjYTIwMTguY3J0MDwGCCsGAQUFBzAChjBodHRwOi8vcXRsc2Nh'.
            'MjAxOC1jYTIuZS1zemlnbm8uaHUvcXRsc2NhMjAxOC5jcnQwPAYIKwYBBQUHMAKG'.
            'MGh0dHA6Ly9xdGxzY2EyMDE4LWNhMy5lLXN6aWduby5odS9xdGxzY2EyMDE4LmNy'.
            'dA=='
        );
        $aia = new AuthorityInformationAccess($binary);
        $this->assertEquals(
            [
              'http://qtlsca2018-ca1.e-szigno.hu/qtlsca2018.crt',
              'http://qtlsca2018-ca2.e-szigno.hu/qtlsca2018.crt',
              'http://qtlsca2018-ca3.e-szigno.hu/qtlsca2018.crt'
            ],
            $aia->getIssuerURIs()
        );
        $this->assertEquals(
            [
              'http://qtlsca2018-ocsp1.e-szigno.hu',
              'http://qtlsca2018-ocsp2.e-szigno.hu',
              'http://qtlsca2018-ocsp3.e-szigno.hu'
            ],
            $aia->getOCSPURIs()
        );
        // This is broken for some reason... Expect no error.
        $binary = base64_decode(
            'MFswNgYIKwYBBQUHMAKGKmh0dHA6Ly9lcC5uYnUuZ292LnNrL3NuY2EvY2VydHMz'.
            'L3NuY2EzLnA3YzAhBggrBgEFBQcwAqQVMBMxETAPBgNVBAUTCFRMSVNLLTgy'
        );
        $aia = new AuthorityInformationAccess($binary);
        // Proprietary OID alongside OCSP. Expect no error..
        $binary = base64_decode(
            'MG4wNgYIKwYBBQUHMAGGKmh0dHBzOi8vaWRlbnRydXN0cm9vdC5vY3NwdG4uaWRl'.
            'bnRydXN0LmNvbTA0BggqhkiG+mUEAYYoaHR0cHM6Ly9pZGVudHJ1c3Ryb290LnRj'.
            'dG4uaWRlbnRydXN0LmNvbQ=='
        );
        $aia = new AuthorityInformationAccess($binary);
        $this->assertEquals(
            [
              'https://identrustroot.ocsptn.identrust.com'
            ],
            $aia->getOCSPURIs()
        );
    }

    public function testBasicConstraints()
    {
        $binary = base64_decode('MAYBAf8CAQA=');
        $basicConstraints = new BasicConstraints($binary);
        $this->assertEquals(
            [
              true,
              0
            ],
            [
              $basicConstraints->isCA(),
              $basicConstraints->getPathLength()
            ]
        );
        $binary = base64_decode('MAMBAf8=');
        $basicConstraints = new BasicConstraints($binary);
        $this->assertEquals(
            [
              true,
              null
            ],
            [
              $basicConstraints->isCA(),
              $basicConstraints->getPathLength()
            ]
        );
    }

    public function testPreCertPoisin()
    {
        $binary = base64_decode('BQA=');
        $preCertPoison = new PreCertPoison($binary, true);
        $this->assertEquals(
            ['isPrecert' => true],
            $preCertPoison->getAttributes()
        );
    }

    public function testExtendedKeyUsage()
    {
        $this->assertTrue(true);
        $binary = base64_decode('MBQGCCsGAQUFBwMBBggrBgEFBQcDAg==');
        $eku = new ExtendedKeyUsage($binary);
        $this->assertEquals(
            [
            'publicKey' => [
              'extendedKeyUsage' => [
                [
                  'name' => 'serverAuth',
                  'oid' => '1.3.6.1.5.5.7.3.1',
                  'url' => 'https://tools.ietf.org/html/rfc5280#section-4.2.1.12'
                ],
                [
                  'name' => 'clientAuth',
                  'oid' => '1.3.6.1.5.5.7.3.2',
                  'url' => 'https://tools.ietf.org/html/rfc5280#section-4.2.1.12'
                ]
              ]
            ]
          ],
            $eku->getAttributes()
        );
        $this->assertEquals(
            [
            $eku->forPurpose('serverAuth'),
            $eku->forPurpose('clientAuth'),
            $eku->forPurpose('codeSigning')
          ],
            [
            true,
            true,
            false
          ]
        );
    }

    public function testSANs()
    {
        $extensionDER = base64_decode(
            'MEyBFXJhZG9taXIuc2ltZWtAbXZjci5jeqAYBgorBgEEAYG4SAQGoAoMCDEwNDU2NjcwoBkGCSsGAQQB3BkCAaAMDAoxODk1MTQwODA4'
        );
        $SAN = new SubjectAltName($extensionDER);
        $this->assertEquals(
            [
            'subject' => [
              'altNames' => [
                'email' => ['radomir.simek@mvcr.cz'],
                'other' => [
                  [
                    'oid' => '1.3.6.1.4.1.23624.4.6',
                    'name' => 'unknown',
                    'value' => 'oAoMCDEwNDU2Njcw'
                  ],
                  [
                    'oid' => '1.3.6.1.4.1.11801.2.1',
                    'name' => 'unknown',
                    'value' => 'oAwMCjE4OTUxNDA4MDg='
                  ],
                ]
              ]
            ]
          ],
            $SAN->getAttributes()
        );
        $finding = $SAN->getFindings()[0]->getFinding();
        $this->assertEquals(
            [
              'severity' => 'warning',
              'component' => 'subjectAltName',
              'message' => 'Unrecognised subjectAltName extension: MEyBFXJhZG9taXIuc2ltZWtAbXZjci5jeqAYBgorBgEEAYG4SAQGoAoMCDEwNDU2NjcwoBkGCSsGAQQB3BkCAaAMDAoxODk1MTQwODA4'
            ],
            [
              'severity' => $finding['severity'],
              'component' => $finding['component'],
              'message' => $finding['message'],
            ]
        );
        $extensionDER = base64_decode(
            'MB+CHXBzZDJodWIucXdhYy5jbGllbnQuYXBpLmtoLmh1'
        );
        $SAN = new SubjectAltName($extensionDER);
        $this->assertEquals(
            [
            'subject' => [
              'altNames' => [
                'DNS' => ['psd2hub.qwac.client.api.kh.hu'],
              ]
            ]
          ],
            $SAN->getAttributes()
        );
        $extensionDER = base64_decode(
            'MBqGGGh0dHBzOi8vd3d3LnRyYWZpY29tLmZpLw=='
        );
        $SAN = new SubjectAltName($extensionDER);
        $this->assertEquals(
            [
            'subject' => [
              'altNames' => [
                'URI' => ['https://www.traficom.fi/'],
              ]
            ]
          ],
            $SAN->getAttributes()
        );
    }

    public function testOCSPNoCheck()
    {
        $der = base64_decode('BQA=');
        $noCheck = new OCSPNoCheck($der);
        $this->assertEquals(
            'This an OCSPNoCheck extension',
            $noCheck->getDescription()
        );
    }

    public function testSCTList()
    {
        $der = base64_decode(
            'BIIBaAFmAHUApLkJkLQYWBSHuxOizGdwCjw1mAT5G9+443fNDsgN3BAAAAFfM3kAlQAABAMARjBEAiBSIhZ9We2EMoQiv7k5P8rCInBSD/9CvQQx0Ge6YKPxYwIgZ5V6IfL4wfJ0pK+8/m/GgAJARpVMqIjHXRTTdi2lRYkAdQDuS723dc5guuFCaR+r4Z5mow9+X7By2IMAxHuJeqj9ywAAAV8zeQK6AAAEAwBGMEQCIFOY6HYwxuwR2mXXbgH80uqWXnVl8ES9X1lY5riQzxNEAiBTwgBV2QPxpTTu4cXs7X7jY0XJfP6Xtly3b/N5c1fbjAB2AN3rHSt6DU+mIIuBrYFocH4ujp0B1VyIjT0RxM227L7MAAABXzN5BUIAAAQDAEcwRQIgWgg98yyRgiFJkn5c3Ebd2zQeHcx0dZ9cLlofkFA1wxECIQC+d4iE/gkFN6c9fYwrxpJC+Kz6IPoRfxc1SyY560sU2A=='
        );
        $sctList = new SCTList($der);
        $this->assertEquals(
            'This is a Signed Certificate Timestamp list extension',
            $sctList->getDescription()
        );
        $this->assertEquals(
            [
            'severity' => 'warning',
            'component' => 'sctList',
            'message' => 'Signed Certificate Timestamp extension not yet supported'
          ],
            $sctList->getFindings()[0]->getFinding()
        );
    }
}
