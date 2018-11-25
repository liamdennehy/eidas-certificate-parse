<?php

namespace eIDASCertificate\tests;

use PHPUnit\Framework\TestCase;
use eIDASCertificate\DataSource;
use eIDASCertificate\TrustedList;
use eIDASCertificate\Certificate\X509Certificate;

class TLTest extends TestCase
{
    private $tlolxml;
    private $tlol;
    private $tls;

    public function setUp()
    {
        if (! $this->tlolxml) {
            $this->tlolxml = DataSource::load(TrustedList::TrustedListOfListsXMLPath);
        }
        if (! $this->tlol) {
            $this->tlol = new TrustedList($this->tlolxml, null, false);
        };
    }

    public function loadAllTLs()
    {
        if (! $this->tls) {
            foreach ($this->tlol->getTrustedListPointers('xml') as $tslPointer) {
                try {
                    $newTL = TrustedList::loadTrustedList($tslPointer);
                    $this->tls[$newTL->getName()] = TrustedList::loadTrustedList($tslPointer);
                } catch (ParseException $e) {
                    // Tolerate unavailable/misbehaving authority
                }
            }
        }
    }
    public function testLoadAllTLs()
    {
        $this->tlol->verifyTSL();
        $this->loadAllTLs();
        $this->assertGreaterThan(
            0,
            sizeof($this->tls)
        );
        foreach ($this->tls as $TrustedList) {
            $this->assertGreaterThan(
                0,
                $TrustedList->getTLX509Certificates()
            );
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
