<?php

namespace eIDASCertificate\tests;

use PHPUnit\Framework\TestCase;
use eIDASCertificate\Certificate\Extension;
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
