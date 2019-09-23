<?php

namespace eIDASCertificate\tests;

use PHPUnit\Framework\TestCase;
use eIDASCertificate\Certificate\Extension;
use eIDASCertificate\Certificate\Extensions;
use eIDASCertificate\Certificate\AuthorityKeyIdentifier;
use eIDASCertificate\Certificate\BasicConstraints;
use eIDASCertificate\Certificate\CRLDistributionPoints;
use eIDASCertificate\Certificate\ExtendedKeyUsage;
use eIDASCertificate\Certificate\KeyUsage;

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
        $extensions = new Extensions($extensionsDER);
        $this->assertEquals(
            [
              'keyUsage',
              'preCertPoison',
              'extKeyUsage',
              'unknown-2.5.29.32',
              'unknown-2.5.29.14',
              'authorityKeyIdentifier',
              'unknown-2.5.29.17',
              'crlDistributionPoints',
              'unknown-1.3.6.1.5.5.7.1.1',
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
            $extnCDPs->getCDPs(),
            [
              'http://qtlsca2018-crl1.e-szigno.hu/qtlsca2018.crl',
              'http://qtlsca2018-crl2.e-szigno.hu/qtlsca2018.crl',
              'http://qtlsca2018-crl3.e-szigno.hu/qtlsca2018.crl'
            ]
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
            base64_encode($aki->getKeyId()),
            'fYROwtRr6sHXIoxow+mg9OyYihw='
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
              false,
              false
            ],
            [
              $basicConstraints->isCA(),
              $basicConstraints->getPathLength()
            ]
        );
    }


    // public function testExtendedKeyUsage()
    // {
    //     $this->assertTrue(true);
    //     $binary = base64_decode('MBQGCCsGAQUFBwMBBggrBgEFBQcDAg==');
    //     $eku = new ExtendedKeyUsage($binary);
    //     $this->assertEquals(
    //         [
    //         $eku->forPurpose('serverAuth'),
    //         $eku->forPurpose('clientAuth'),
    //         $eku->forPurpose('codeSigning')
    //       ],
    //         [
    //         true,
    //         true,
    //         false
    //       ]
    //     );
    // }
}
