<?php

namespace eIDASCertificate\tests;

use PHPUnit\Framework\TestCase;
use eIDASCertificate\DataSource;
use eIDASCertificate\TrustedList;
use eIDASCertificate\ParseException;
use eIDASCertificate\Certificate\X509Certificate;

class TLOLRootTest extends TestCase
{
    private $tlolxml;
    private $tlol;

    public function setUp()
    {
        if (! $this->tlolxml) {
            $this->tlolxml = DataSource::load(
                TrustedList::TrustedListOfListsXMLPath
            );
        };
        if (! $this->tlol) {
            $this->tlol = new TrustedList($this->tlolxml, null, false);
        };
        // if ($this->tlol->getSignedBy()) {
        //     DataSource::persist(TrustedList::TrustedListOfListsXMLPath);
        // }
    }

    public function testTLOLAttributes()
    {
        $this->assertEquals(
            "EUlistofthelists",
            $this->tlol->getTSLType()->getType()
        );
        $this->assertInternalType("int", $this->tlol->getVersionID());
        $this->assertInternalType("int", $this->tlol->getSequenceNumber());
        $this->assertEquals(
            5,
            $this->tlol->getVersionID()
        );
        $this->assertGreaterThan(
            1,
            $this->tlol->getSequenceNumber()
        );
    }

    public function testTLOLCertificates()
    {
        $this->assertGreaterThan(
            0,
            sizeof($this->tlol->getTLX509Certificates())
        );
        foreach ($this->tlol->getTLX509Certificates() as $tlolCert) {
            $this->assertGreaterThan(
                12,
                strlen(X509Certificate::getDN($tlolCert))
            );
        }
    }

    public function testVerifyTLOL()
    {
        $expectedSignedByDNArray =
        [
            'C' => 'NL',
            'L' => 'BE',
            'O' => 'European Commission',
            'OU' => '0949.383.342',
            'CN' => 'Michael Theodoor de Boer',
            'SN' => 'de Boer',
            'GN' => 'Michael Theodoor',
            'serialNumber' => '10303969450085046424',
            'emailAddress' => 'michael.de-boer@ec.europa.eu',
            'title' => 'Professional Person'
        ];
        $this->assertTrue($this->tlol->verifyTSL());
        $tlolSignedByCert = $this->tlol->getSignedBy();
        $tlolSignedByDNArray = openssl_x509_parse($tlolSignedByCert)['subject'];
        $this->assertEquals(
            $expectedSignedByDNArray,
            $tlolSignedByDNArray
        );
    }

    public function testGetTLOLTrustedListXMLPointers()
    {
        $validURLFilterFlags =
            FILTER_FLAG_PATH_REQUIRED |
            FILTER_FLAG_HOST_REQUIRED |
            FILTER_FLAG_SCHEME_REQUIRED;
        $tlXMLPointers = $this->tlol->getTrustedListPointers('xml');
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
