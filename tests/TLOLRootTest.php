<?php

namespace eIDASCertificate\tests;

use PHPUnit\Framework\TestCase;
use eIDASCertificate\DataSource;
use eIDASCertificate\TrustedList;

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
            openssl_x509_parse($TrustedListOfLists->getSignedBy())['subject']
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
        $this->assertGreaterThan(
            0,
            sizeof($this->tlol->getTrustedListPointers())
        );
    }

    public function testGetTLOLTrustedLists()
    {
        if (! $this->tlol) {
            $TrustedListOfLists = new TrustedList($this->tlolxml, null, false);
            $TrustedListOfLists->verifyTSL();
            $this->tlol = $TrustedListOfLists;
        };
        $tls = $this->tlol->getTrustedLists();
        $this->assertGreaterThan(
            0,
            sizeof($tls)
        );
    }

    public function testAllTLsVerified()
    {
        if (! $this->tlol) {
            $TrustedListOfLists = new TrustedList($this->tlolxml, null, false);
            $TrustedListOfLists->verifyTSL();
            $this->tlol = $TrustedListOfLists;
        };
        $tls = $this->tlol->getTrustedLists();
        $failedTLVerify = false;
        foreach ($tls as $tl) {
            if (! $tl->getSignedBy()) {
                $failedTLVerify = true;
            }
        };
        $this->assertFalse($failedTLVerify);
        $this->assertTrue($this->tlol->verifyAllTLs());
    }
}
