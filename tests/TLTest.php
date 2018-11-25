<?php

namespace eIDASCertificate\tests;

use PHPUnit\Framework\TestCase;
use eIDASCertificate\DataSource;
use eIDASCertificate\TrustedList;

class TLTest extends TestCase
{
    private $tlolxml;
    private $tlol;
    public function setUp()
    {
        if (! $this->tlolxml) {
            $this->tlolxml = DataSource::load('tlol.xml');
        }
    }

    public function testVerifyAllTLs()
    {
        $tlolxml=DataSource::load(TrustedList::TrustedListOfListsXMLPath);
        $TrustedListOfLists = new TrustedList($tlolxml, null, false);
        $TrustedListOfLists->verifyTSL();
        $this->assertTrue($TrustedListOfLists->verifyAllTLs());
        $failedTLVerify = false;
        foreach ($TrustedListOfLists as $tl) {
            if (! $tl->getSignedBy) {
                $failedTLVerify = true;
            }
        };
        $this->assertFalse($failedTLVerify);
    }
}
