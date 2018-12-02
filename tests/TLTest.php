<?php

namespace eIDASCertificate\tests;

use PHPUnit\Framework\TestCase;
use eIDASCertificate\DataSource;
use eIDASCertificate\TrustedList;
use eIDASCertificate\TrustedList\TSLType;
use eIDASCertificate\Certificate\X509Certificate;

class TLTest extends TestCase
{
    private $tlolxml;
    private $tlol;
    private $tls;
    private $tlxml;
    private $tl;

    public function setUp()
    {
        if (! $this->tlolxml) {
            $this->tlolxml=file_get_contents('data/tlol.xml');
        }
        if (! $this->tlxml) {
            $this->tlxml=file_get_contents('data/badtl.xml');
        }
        if (! $this->tlol) {
            $this->tlol = new TrustedList($this->tlolxml, null, false);
        };
        if (! $this->tl) {
            $this->tl = new TrustedList($this->tlxml, null, false);
        };
    }

    public function testLoadBadTL()
    {
        $this->tl = new TrustedList($this->tlxml, null, false);
        $this->assertEquals(
            2,
            strlen($this->tl->getSchemeTerritory())
        );
        $this->assertGreaterThan(
            10,
            strlen($this->tl->getSchemeOperatorName())
        );
        $this->assertInternalType("int", $this->tl->getListIssueDateTime());
        $this->assertGreaterThan(1262300400, $this->tl->getListIssueDateTime());
        $this->assertInternalType("int", $this->tl->getNextUpdate());
        $this->assertGreaterThan(1262300400, $this->tl->getNextUpdate());
        $this->assertGreaterThan($this->tl->getListIssueDateTime(), $this->tl->getNextUpdate());
        $this->assertInstanceOf(TSLType::class, $this->tl->getTSLType());
        $this->assertEquals(
            "EUgeneric", $this->tl->getTSLType()->getType());
        foreach ($this->tl->getDistributionPoints() as $dp) {
            $this->assertEquals(
                $dp, filter_var(
                    $dp,
                    FILTER_VALIDATE_URL,
                    FILTER_FLAG_PATH_REQUIRED | FILTER_FLAG_HOST_REQUIRED));
            };
    }

    public function loadAllTLs()
    {
        if (! $this->tls) {
            foreach ($this->tlol->getTrustedListPointers('xml') as $tslPointer) {
                try {
                    $newTL = TrustedList::loadTrustedList($tslPointer);
                    $this->tls[$tslPointer->getName()] = TrustedList::loadTrustedList($tslPointer);
                } catch (ParseException $e) {
                    // Tolerate unavailable/misbehaving authority
                }
            }
        }
    }

    public function testLoadAllTLPointers()
    {
        $this->assertGreaterThan(
            12,
            sizeof($this->tlol->getTrustedListPointers('xml'))
        );
    }

    // public function testVerifyAllTLs()
    // {
    //     $this->tlol->verifyTSL();
    //     $this->tlol->setTolerateFailedTLs(true);
    //     $this->assertTrue($this->tlol->verifyAllTLs());
    // }
}
