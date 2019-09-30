<?php

namespace eIDASCertificate\tests;

use PHPUnit\Framework\TestCase;
use eIDASCertificate\DataSource;
use eIDASCertificate\TrustedList;
use eIDASCertificate\TrustedList\TSLType;
use eIDASCertificate\TrustedList\TSLPointer;
use eIDASCertificate\DigitalIdentity\ServiceDigitalIdentity;
use eIDASCertificate\Certificate\X509Certificate;
use DateTime;

class TLTest extends TestCase
{
    const lotlXMLFileName = 'eu-lotl.xml';
    const nltlAttributes = [
        'schemeTerritory' => 'NL',
        'schemeOperatorName' => 'Radiocommunications Agency',
        'tslSequenceNumber' => 44,
        'tslSignedByHash' => 'def82d40878a148e21fcacbcbfdf7623ed9d6ca149d631ca1ed61051827f31fc',
    ];

    private $tlolxml;
    private $tlol;
    private $tls;
    private $tlxml;
    private $tl;
    private $tslPointers;
    private $testSchemeTerritories;

    public function setUp()
    {
        $this->datadir = __DIR__ . '/../data';
        $xmlFilePath = $this->datadir.'/'.self::lotlXMLFileName;
        if (! file_exists($xmlFilePath)) {
            $this->lotlXML = DataSource::getHTTP(
                TrustedList::ListOfTrustedListsXMLPath
            );
            file_put_contents($xmlFilePath, $this->lotlXML);
        } else {
            $this->lotlXML = file_get_contents($xmlFilePath);
        }
        $this->lotl = new TrustedList($this->lotlXML);
        // if (! $this->tlolxml) {
        //     $this->tlolxml=file_get_contents('data/eu-lotl.xml');
        // }
        // if (! $this->tlol) {
        //     $this->tlol = new TrustedList($this->tlolxml, null, false);
        // };
        if (! $this->testSchemeTerritories) {
            $this->testSchemeTerritories = ['HU','DE','SK'];
        }
        // if (! $this->tls) {
        //     foreach ($this->testSchemeTerritories as $schemeTerritory) {
        //         $this->tls[$schemeTerritory] = $this->loadTL($schemeTerritory);
        //     };
        // }
    }

    public static function getNLTLAttributes()
    {
        $tlAttributes = self::nltlAttributes;
        $tlAttributes['parentTSL'] = LOTLRootTest::getLOTLAttributes();
        return $tlAttributes;
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
                    FILTER_FLAG_PATH_REQUIRED
                    // FILTER_FLAG_PATH_REQUIRED |
                    // FILTER_FLAG_HOST_REQUIRED |
                    // FILTER_FLAG_SCHEME_REQUIRED
                )
            );
        };
        $this->assertEquals(64, strlen($thistl->getXMLHash()));
    }

    public function testTLPointers()
    {
        foreach ($this->testSchemeTerritories as $schemeTerritory) {
            $tslPointers = $this->lotl->getTrustedListPointer($schemeTerritory);
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
            $x509Certificates = [];
            foreach ($tslPointer->getServiceDigitalIdentities() as $sdi) {
                $this->assertInstanceOf(ServiceDigitalIdentity::class, $sdi);
                $this->assertGreaterThan(
                    0,
                    $sdi->getX509Certificates()
                );
                foreach ($sdi->getX509Certificates() as $x509Certificate) {
                    $x509Certificates[] = $x509Certificate;
                }
            }
            $this->assertGreaterThan(
                0,
                sizeof($x509Certificates)
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
                    FILTER_FLAG_PATH_REQUIRED
                    // FILTER_FLAG_PATH_REQUIRED |
                    // FILTER_FLAG_HOST_REQUIRED |
                    // FILTER_FLAG_SCHEME_REQUIRED
                )
            );
        };
    }

    // public function loadTL($schemeTerritory)
    // {
    //     $tslPointers = $this->tlol->getTrustedListPointer($schemeTerritory);
    //     $newTL = TrustedList::loadFromPointer($tslPointers[0]);
    //     return $newTL;
    // }
    //
    public function testLoadTLs()
    {
        $crtFileName = $this->datadir.'/'.LOTLRootTest::lotlSigningCertPath;
        $crt = file_get_contents($crtFileName);
        $rightCert = new X509Certificate(file_get_contents($crtFileName));
        $lotl = $this->lotl;
        $lotl->verifyTSL($rightCert);
        $lotlHash = hash('sha256', $this->lotlXML);
        $this->assertEquals(
            $lotlHash,
            hash('sha256', $lotl->getXML())
        );
        $this->assertEquals(
            $lotlHash,
            $lotl->getXMLHash()
        );

        $nlFile = $this->datadir.'/tl-52f7b34b484ce888c5f1d277bcb2bfbff0b1d3bbf11217a44090fab4b6a83fd3.xml';
        $lotl->addTrustedListXML("NL: Radiocommunications Agency", file_get_contents($nlFile));
        $now = (new DateTime('now'))->format('U');
        $nlTL = $lotl->getTrustedLists()["NL: Radiocommunications Agency"];
        $nlTLRefAttributes = self::getNLTLAttributes();
        $nlTLTestAttributes = $nlTL->getTrustedListAtrributes();
        $this->assertArrayHasKey(
            'tslSignatureVerifiedAt',
            $nlTLTestAttributes['parentTSL']
        );
        $this->assertArrayHasKey(
            'tslSignatureVerifiedAt',
            $nlTLTestAttributes
        );
        $this->assertGreaterThan(
            $now - 10,
            $nlTLTestAttributes['tslSignatureVerifiedAt']
        );
        $this->assertLessThanOrEqual(
            $now,
            $nlTLTestAttributes['tslSignatureVerifiedAt']
        );
        unset($nlTLTestAttributes['tslSignatureVerifiedAt']);
        unset($nlTLTestAttributes['parentTSL']['tslSignatureVerifiedAt']);
        $this->assertEquals(
            $nlTLRefAttributes,
            $nlTLTestAttributes
        );
    }

    // public function testTLAttributes()
    // {
    //     foreach ($this->testSchemeTerritories as $schemeTerritory) {
    //         $this->TLAttributeTests($this->tls[$schemeTerritory]);
    //     };
    // }

    // public function testVerifyAllTLs()
    // {
    //     $this->tlol->verifyTSL();
    //     $this->tlol->setTolerateFailedTLs(true);
    //     $this->assertTrue($this->tlol->verifyAllTLs());
    // }
}
