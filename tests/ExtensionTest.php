<?php

namespace eIDASCertificate\tests;

use PHPUnit\Framework\TestCase;
use eIDASCertificate\Certificate\Extension;
use eIDASCertificate\Certificate\Extensions;
use eIDASCertificate\Certificate\CRLDistributionPoints;
use FG\ASN1\ASNObject;

class ExtensionTest extends TestCase
{
    // public function setUp()
    // {
    //     $this->datadir = __DIR__ . '/../data';
    //     $xmlFilePath = $this->datadir.self::lotlXMLFileName;
    //     if (! file_exists($xmlFilePath)) {
    //         $this->lotlXML = DataSource::getHTTP(
    //             TrustedList::ListOfTrustedListsXMLPath
    //         );
    //         file_put_contents($xmlFilePath, $this->lotlXML);
    //     } else {
    //         $this->lotlXML = file_get_contents($xmlFilePath);
    //     }
    // }

    public function testExtensions()
    {
        $extensionsDER = base64_decode("MIIFFDAOBgNVHQ8BAf8EBAMCBaAwEwYKKwYBBAHWeQIEAwEB/wQCBQAwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMIIBXQYDVR0gBIIBVDCCAVAwggE3Bg8rBgEEAYGoGAIBAYEqAgkwggEiMCYGCCsGAQUFBwIBFhpodHRwOi8vY3AuZS1zemlnbm8uaHUvcWNwczBEBggrBgEFBQcCAjA4DDZRdWFsaWZpZWQgUFNEMiBjZXJ0aWZpY2F0ZSBmb3Igd2Vic2l0ZSBhdXRoZW50aWNhdGlvbi4wNAYIKwYBBQUHAgIwKAwmT3JnYW5pemF0aW9uYWwgdmFsaWRhdGlvbiBjZXJ0aWZpY2F0ZS4wRQYIKwYBBQUHAgIwOQw3TWluxZFzw610ZXR0IFBTRDIgd2Vib2xkYWwtaGl0ZWxlc8OtdMWRIHRhbsO6c8OtdHbDoW55LjA1BggrBgEFBQcCAjApDCdTemVydmV6ZXQtZWxsZW7FkXJ6w7Z0dCB0YW7DunPDrXR2w6FueS4wCQYHBACBmCcDATAIBgZngQwBAgIwHQYDVR0OBBYEFCI7XaCk9Uctd6iTKpvkp0m19TRqMB8GA1UdIwQYMBaAFH2ETsLUa+rB1yKMaMPpoPTsmIocMCgGA1UdEQQhMB+CHXBzZDJodWIucXdhYy5jbGllbnQuYXBpLmtoLmh1MIG2BgNVHR8Ega4wgaswN6A1oDOGMWh0dHA6Ly9xdGxzY2EyMDE4LWNybDEuZS1zemlnbm8uaHUvcXRsc2NhMjAxOC5jcmwwN6A1oDOGMWh0dHA6Ly9xdGxzY2EyMDE4LWNybDIuZS1zemlnbm8uaHUvcXRsc2NhMjAxOC5jcmwwN6A1oDOGMWh0dHA6Ly9xdGxzY2EyMDE4LWNybDMuZS1zemlnbm8uaHUvcXRsc2NhMjAxOC5jcmwwggFfBggrBgEFBQcBAQSCAVEwggFNMC8GCCsGAQUFBzABhiNodHRwOi8vcXRsc2NhMjAxOC1vY3NwMS5lLXN6aWduby5odTAvBggrBgEFBQcwAYYjaHR0cDovL3F0bHNjYTIwMTgtb2NzcDIuZS1zemlnbm8uaHUwLwYIKwYBBQUHMAGGI2h0dHA6Ly9xdGxzY2EyMDE4LW9jc3AzLmUtc3ppZ25vLmh1MDwGCCsGAQUFBzAChjBodHRwOi8vcXRsc2NhMjAxOC1jYTEuZS1zemlnbm8uaHUvcXRsc2NhMjAxOC5jcnQwPAYIKwYBBQUHMAKGMGh0dHA6Ly9xdGxzY2EyMDE4LWNhMi5lLXN6aWduby5odS9xdGxzY2EyMDE4LmNydDA8BggrBgEFBQcwAoYwaHR0cDovL3F0bHNjYTIwMTgtY2EzLmUtc3ppZ25vLmh1L3F0bHNjYTIwMTguY3J0MIHmBggrBgEFBQcBAwSB2TCB1jAIBgYEAI5GAQEwCwYGBACORgEDAgEKMFMGBgQAjkYBBTBJMCQWHmh0dHBzOi8vY3AuZS1zemlnbm8uaHUvcWNwc19lbhMCRU4wIRYbaHR0cHM6Ly9jcC5lLXN6aWduby5odS9xY3BzEwJIVTATBgYEAI5GAQYwCQYHBACORgEGAzBTBgYEAIGYJwIwSTAmMBEGBwQAgZgnAQIMBlBTUF9QSTARBgcEAIGYJwEDDAZQU1BfQUkMF0NlbnRyYWwgQmFuayBvZiBIdW5nYXJ5DAZIVS1DQkg=");
        $extensions = new Extensions($extensionsDER);
        $this->assertEquals(
            [
            'preCertPoison',
            'extKeyUsage',
            'unknown-2.5.29.32',
            'unknown-2.5.29.14',
            'authorityKeyIdentifier',
            'unknown-2.5.29.17',
            'crlDistributionPoints',
            'unknown-1.3.6.1.5.5.7.1.1'
          ],
            array_keys($extensions->getExtensions())
        );
        // TODO: Throw a full Extensions block at Extensions class and test result has right entries
    }

    public function testCRLDistributionPoints()
    {
        $this->assertTrue(true);
        $binary = base64_decode('MIGrMDegNaAzhjFodHRwOi8vcXRsc2NhMjAxOC1jcmwxLmUtc3ppZ25vLmh1L3F0bHNjYTIwMTguY3JsMDegNaAzhjFodHRwOi8vcXRsc2NhMjAxOC1jcmwyLmUtc3ppZ25vLmh1L3F0bHNjYTIwMTguY3JsMDegNaAzhjFodHRwOi8vcXRsc2NhMjAxOC1jcmwzLmUtc3ppZ25vLmh1L3F0bHNjYTIwMTguY3Js');
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
}
