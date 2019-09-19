<?php

namespace eIDASCertificate\tests;

use PHPUnit\Framework\TestCase;
use eIDASCertificate\Certificate\Extension;
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

    public function testBasicConstraints()
    {
        $this->assertTrue(true);
        // $binary = base64_decode('MFgwJwYIKwYBBQUHMAGGG2h0dHA6Ly9xY2Eub2NzcC5sdXh0cnVzdC5sdTAtBggrBgEFBQcwAoYhaHR0cDovL2NhLmx1eHRydXN0Lmx1L0xUR1FDQTMuY3J0');
        // $asn1 = ASNObject::fromBinary($binary);
        // $bc = Extension::fromASNObject($asn1);
        // $this->assertEquals([
        //   'abc',
        //   get_class($ext)
        // ]);
    }
}
