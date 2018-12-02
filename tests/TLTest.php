<?php

namespace eIDASCertificate\tests;

use PHPUnit\Framework\TestCase;
use eIDASCertificate\DataSource;
use eIDASCertificate\TrustedList;
use eIDASCertificate\TrustedList\TSLType;
use eIDASCertificate\TrustedList\TSLPointer;
use eIDASCertificate\Certificate\X509Certificate;

class TLTest extends TestCase
{
    private $tlolxml;
    private $tlol;
    private $tls;
    private $tlxml;
    private $tl;
    private $tslPointers;
    private $testSchemeTerritories;

    public function setUp()
    {
        if (! $this->tlolxml) {
            $this->tlolxml=file_get_contents('data/tlol.xml');
        }
        if (! $this->tlol) {
            $this->tlol = new TrustedList($this->tlolxml, null, false);
        };
        if (! $this->testSchemeTerritories) {
            $this->testSchemeTerritories = ['HU','DE','SK'];
        }
    }

    public function TLAttributeTests($thistl)
    {
        $this->assertEquals(
            2,
            strlen($thistl->getSchemeTerritory())
        );
        $this->assertGreaterThan(
            10,
            strlen($thistl->getSchemeOperatorName())
        );
        $this->assertInternalType("int", $thistl->getListIssueDateTime());
        $this->assertGreaterThan(1262300400, $thistl->getListIssueDateTime());
        $this->assertInternalType("int", $thistl->getNextUpdate());
        $this->assertGreaterThan(1262300400, $thistl->getNextUpdate());
        $this->assertGreaterThan($thistl->getListIssueDateTime(), $thistl->getNextUpdate());
        $this->assertInstanceOf(TSLType::class, $thistl->getTSLType());
        $this->assertEquals(
            "EUgeneric",
            $thistl->getTSLType()->getType()
        );
        foreach ($thistl->getDistributionPoints() as $dp) {
            $this->assertEquals(
                $dp,
                filter_var(
                    $dp,
                    FILTER_VALIDATE_URL,
                    FILTER_FLAG_PATH_REQUIRED |
                    FILTER_FLAG_HOST_REQUIRED |
                    FILTER_FLAG_SCHEME_REQUIRED
                )
            );
        };
        $this->assertEquals(64, strlen($thistl->getXMLHash()));
    }

    public function testTLPointers()
    {
        foreach ($this->testSchemeTerritories as $schemeTerritory) {
            $tslPointers = $this->tlol->getTrustedListPointer($schemeTerritory);
            $this->assertEquals(
                1,
                sizeof($tslPointers)
            );
            $tslPointer = $tslPointers[0];
            $this->assertInstanceOf(TSLPointer::class, $tslPointer);
            $this->assertGreaterThan(
                0,
                $tslPointer->getServiceDigitalIdentities()
            );
            $this->assertEquals(
                'application/vnd.etsi.tsl+xml',
                $tslPointer->getTSLMimeType()
            );
            $this->assertEquals(
                $tslPointer->getTSLLocation(),
                filter_var(
                    $tslPointer->getTSLLocation(),
                    FILTER_VALIDATE_URL,
                    FILTER_FLAG_PATH_REQUIRED |
                    FILTER_FLAG_HOST_REQUIRED |
                    FILTER_FLAG_SCHEME_REQUIRED
                )
            );

        };
        // $tlHUXML = DataSource::load($tlHUPointers[0]->getTSLLocation());
        // $tlHU = new TrustedList($tlHUXML, $tlHUPointers[0]);
        // $this->TLAttributeTests($tlHU);
        // $this->TLAttributeTests(DataSource::load('https://www.digst.dk/TSLDKxml'));
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
