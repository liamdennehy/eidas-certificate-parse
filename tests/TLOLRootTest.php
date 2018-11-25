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
        if ($this->tlol->getSignedBy()) {
            DataSource::persist(TrustedList::TrustedListOfListsXMLPath);
        }
    }

    public function testTLOLCertificates()
    {
        $this->assertGreaterThan(
            0,
            sizeof($this->tlol->getTLX509Certificates())
        );
        foreach ($this->tlol->getTLX509Certificates() as $tlolCert) {
            $this->assertGreaterThan(
                0,
                strlen(X509Certificate::getDN($tlolCert))
            );
        }
    }

    public function testVerifyTLOL()
    {
        $this->tlol->verifyTSL();
        $this->assertEquals(
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
            ],
            openssl_x509_parse(
                $this->tlol->getSignedBy()
                )['subject']
        );
    }

    public function testGetTLOLTrustedListPointers()
    {
        $tlPointers = $this->tlol->getTrustedListPointers('xml');
        $this->assertGreaterThan(
            0,
            sizeof($tlPointers)
        );
    }
}
