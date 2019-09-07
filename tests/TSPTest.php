<?php

namespace eIDASCertificate\tests;

use PHPUnit\Framework\TestCase;
use eIDASCertificate\DataSource;
use eIDASCertificate\TrustedList;
use eIDASCertificate\Certificate\X509Certificate;

class TSPTest extends TestCase
{
    private $lotlxml;
    private $lotl;
    private $tls;
    private $dataSource;

    public function setUp()
    {
        if (! $this->dataSource) {
            $this->dataSource = new DataSource("sqlite", "/data");
        }
        if (! $this->lotlxml) {
            $this->lotlxml = $this->dataSource->load(TrustedList::ListOfTrustedListsXMLPath, 'trustedLists');
        }
        if (! $this->lotl) {
            $this->lotl = new TrustedList(
                file_get_contents(__DIR__ . '/../data/eu-lotl.xml')
            );
        };
    }

    public function loadAllTLs()
    {
        if (! $this->tls) {
            foreach ($this->lotl->getTrustedListPointers('xml') as $tslPointer) {
                try {
                    $newTL = TrustedList::loadTrustedList($tslPointer);
                    $this->tls[$newTL->getName()] = TrustedList::loadTrustedList($tslPointer);
                } catch (ParseException $e) {
                    // Tolerate unavailable/misbehaving authority
                }
            }
        }
    }

    public function testTrue()
    {
        $this->assertTrue(true);
    }
    // public function testLoadAllTSPs()
    // {
    //     $this->lotl->verifyTSL();
    //     $this->loadAllTLs();
    //     $this->assertGreaterThan(
    //         0,
    //         sizeof($this->tls)
    //     );
    //     foreach ($this->tls as $TrustedList) {
    //         $this->assertGreaterThan(
    //             0,
    //             $TrustedList->getTLX509Certificates()
    //         );
    //     }
    // }
    //
    // public function testVerifyAllTLs()
    // {
    //     $lotlxml=DataSource::load(TrustedList::TrustedListOfListsXMLPath);
    //     $TrustedListOfLists = new TrustedList($lotlxml, null, false);
    //     $TrustedListOfLists->verifyTSL();
    //     $this->assertTrue($TrustedListOfLists->verifyAllTLs());
    //     $failedTLVerify = false;
    //     foreach ($TrustedListOfLists as $tl) {
    //         if (! $tl->getSignedBy) {
    //             $failedTLVerify = true;
    //         }
    //     };
    //     $this->assertFalse($failedTLVerify);
    // }
}
