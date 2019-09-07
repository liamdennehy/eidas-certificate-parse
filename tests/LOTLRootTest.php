<?php

namespace eIDASCertificate\tests;

use PHPUnit\Framework\TestCase;
use eIDASCertificate\DataSource;
use eIDASCertificate\TrustedList;
use eIDASCertificate\ParseException;
use eIDASCertificate\Certificate\X509Certificate;

class LOTLRootTest extends TestCase
{
    private $lotlxml;
    private $lotl;

    public function setUp()
    {
        if (! $this->lotlxml) {
            $this->lotlxml = DataSource::load(
                TrustedList::ListOfTrustedListsXMLPath
            );
        };
        if (! $this->lotl) {
            $this->lotl = new TrustedList($this->lotlxml, null, false);
        };
    }

    public function testLOTLAttributes()
    {
        $this->assertEquals(
            "EUlistofthelists",
            $this->lotl->getTSLType()->getType()
        );
        $this->assertInternalType("int", $this->lotl->getVersionID());
        $this->assertInternalType("int", $this->lotl->getSequenceNumber());
        $this->assertEquals(
            5,
            $this->lotl->getVersionID()
        );
        $this->assertGreaterThan(
            1,
            $this->lotl->getSequenceNumber()
        );
    }

    public function testLOTLCertificates()
    {
        $this->assertGreaterThan(
            0,
            sizeof($this->lotl->getTLX509Certificates())
        );
        foreach ($this->lotl->getTLX509Certificates() as $lotlCert) {
            $this->assertGreaterThan(
                12,
                strlen(X509Certificate::getDN($lotlCert))
            );
        }
    }

    public function testVerifyLOTL()
    {
        // $expectedSignedByDNArray =
        // [
        //     'C' => 'NL',
        //     'L' => 'BE',
        //     'O' => 'European Commission',
        //     'OU' => '0949.383.342',
        //     'CN' => 'Michael Theodoor de Boer',
        //     'SN' => 'de Boer',
        //     'GN' => 'Michael Theodoor',
        //     'serialNumber' => '10303969450085046424',
        //     'emailAddress' => 'michael.de-boer@ec.europa.eu',
        //     'title' => 'Professional Person'
        // ];
        $this->assertTrue($this->lotl->verifyTSL());
        // $lotlSignedByCert = $this->lotl->getSignedBy();
        // $lotlSignedByDNArray = openssl_x509_parse($lotlSignedByCert)['subject'];
        // $this->assertEquals(
        //     $expectedSignedByDNArray,
        //     $lotlSignedByDNArray
        // );
    }

    public function testGetLOTLTrustedListXMLPointers()
    {
        $validURLFilterFlags =
            FILTER_FLAG_PATH_REQUIRED;
        // FILTER_FLAG_PATH_REQUIRED |
        // FILTER_FLAG_HOST_REQUIRED |
        // FILTER_FLAG_SCHEME_REQUIRED;
        $tlXMLPointers = $this->lotl->getTrustedListPointers('xml');
        $this->assertGreaterThan(
            12,
            sizeof($tlXMLPointers)
        );
        foreach ($tlXMLPointers as $tlPointer) {
            $this->assertEquals(
                "application/vnd.etsi.tsl+xml",
                $tlPointer->getTSLMimeType()
            );
            $dp = $tlPointer->getTSLLocation();
            $this->assertEquals(
                $dp,
                filter_var(
                    $dp,
                    FILTER_VALIDATE_URL,
                    $validURLFilterFlags
                )
            );
        };
    }
}
