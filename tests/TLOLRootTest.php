<?php

namespace eIDASCertificate\tests;

use PHPUnit\Framework\TestCase;
use eIDASCertificate\DataSource;
use eIDASCertificate\TrustedList;

class TLOLRootTest extends TestCase
{
    private $tlolxml;
    public function setUp()
    {
        if (! $this->tlolxml) {
            $this->tlolxml = DataSource::fetch(
                TrustedList::TrustedListOfListsXMLPath);
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
    }

    public function testVerifyAllTLs()
    {
        $TrustedListOfLists = new TrustedList($this->tlolxml, null, false);
        $TrustedListOfLists->verifyTSL();
        $this->assertTrue($TrustedListOfLists->verifyAllTLs(true));
        $failedTLVerify = false;
        foreach ($TrustedListOfLists as $tl) {
            if (! $tl->getSignedBy) {
                $failedTLVerify = true;
            }
        };
        $this->assertFalse($failedTLVerify);
    }
}
