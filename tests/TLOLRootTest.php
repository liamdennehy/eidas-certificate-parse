<?php

namespace eIDASCertificate\tests;

use PHPUnit\Framework\TestCase;
use eIDASCertificate\DataSource;
use eIDASCertificate\TrustedList;
use eIDASCertificate\Certificate\X509Certificate;

class TLOLRootTest extends TestCase
{
    private $tlolxml;
    private $tlol;
    public function setUp()
    {
        if (! $this->tlolxml) {
            $this->tlolxml = DataSource::fetch(
                TrustedList::TrustedListOfListsXMLPath
            );
        }
    }

    public function testTLOLCertificates()
    {
        $TrustedListOfLists = new TrustedList($this->tlolxml, null, false);
        $this->assertGreaterThan(
            0,
            sizeof($TrustedListOfLists->getTLX509Certificates())
        );
        foreach ($TrustedListOfLists->getTLX509Certificates() as $tlolCert) {
            $this->assertGreaterThan(
                0,
                strlen(X509Certificate::getDN($tlolCert))
            );
        }
    }

    public function testVerifyTLOL()
    {
        $TrustedListOfLists = new TrustedList($this->tlolxml, null, false);
        $TrustedListOfLists->verifyTSL();
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
                $TrustedListOfLists->getSignedBy()
                )['subject']
        );
        $this->tlol = $TrustedListOfLists;
    }

    public function testGetTLOLTrustedListPointers()
    {
        if (! $this->tlol) {
            $TrustedListOfLists = new TrustedList($this->tlolxml, null, false);
            $TrustedListOfLists->verifyTSL();
            $this->tlol = $TrustedListOfLists;
        };
        $tlPointers = $this->tlol->getTrustedListPointers('xml');
        $this->assertGreaterThan(
            0,
            sizeof($tlPointers)
        );
    }
}
