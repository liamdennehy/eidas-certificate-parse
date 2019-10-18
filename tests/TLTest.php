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
use eIDASCertificate\tests\Helper;

class TLTest extends TestCase
{
    const lotlXMLFileName = 'eu-lotl.xml';
    const testTLName = 'BE: FPS Economy, SMEs, Self-employed and Energy - Quality and Safety';
    const testTLURI = 'https://tsl.belgium.be/tsl-be.xml';
    const testTLXMLFileName = 'tl-61c0487109be27255c19cff26d8f56bea621e7f381a7b4cbe7fb4750bd477bf9.xml';
    const testTLAttributes = [
        'schemeTerritory' => 'BE',
        'schemeOperator' => [
          'name' => 'FPS Economy, SMEs, Self-employed and Energy - Quality and Safety',
          'names' => [
            [
              'lang' => 'en',
              'name' => 'FPS Economy, SMEs, Self-employed and Energy - Quality and Safety'
            ],
            [
              'lang' => 'nl',
              'name' => 'FOD Economie, KMO, Middenstand en Energie - Kwaliteit en Veiligheid'
            ],
            [
              'lang' => 'fr',
              'name' => 'SPF Economie, PME, Classes moyennes et Energie - Qualité et Sécurité'
            ],
            [
              'lang' => 'de',
              'name' => 'FÖD Wirtschaft, KMU, Mittelstand und Energie - Qualität und Sicherheit'
            ],
          ],
          'postalAddresses' => [
            'en' => [
              'StreetAddress' => 'NG III - Koning Albert II-laan 16',
              'Locality' => 'Brussels',
              'PostalCode' => '1000',
              'StateOrProvince' => 'Brussels',
              'CountryName' => 'BE'
            ],
            'nl' => [
              'StreetAddress' => 'NG III - Koning Albert II-laan 16',
              'Locality' => 'Brussel',
              'PostalCode' => '1000',
              'StateOrProvince' => 'Brussel',
              'CountryName' => 'BE'
            ],
          ],
          'electronicAddresses' => [
            [
              'lang' => 'en',
              'uri' => 'http://economie.fgov.be'
            ],
            [
              'lang' => 'en',
              'uri' => 'mailto:be.sign@economie.fgov.be'
            ],
          ]
        ],
        'sequenceNumber' => 44,
        'informationURIs' => [
          ['lang' => 'en', 'uri' => 'https://tsl.belgium.be/']
        ],
        'sourceURI' => 'https://tsl.belgium.be/tsl-be.xml',
        'issued' => '1567641600',
        'nextUpdate' => '1583107200',
        'fileHash' => '48d9f7ec51ed0be4f1b52ef5fbdcb0b69a62a766291b2bcb46b332b7a0cdc475',
        'signature' => [
          'signerThumbprint' => 'cfde6ceda889bd628bde8ed18092b06392d23cf2'
        ]
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
        Helper::getHTTP(self::testTLURI, 'tl');
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
        if (! $this->testSchemeTerritories) {
            $this->testSchemeTerritories = ['HU','DE','SK'];
        }
    }

    public static function getTestTLAttributes()
    {
        $tlAttributes = self::testTLAttributes;
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
                )
            );
        };
    }

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

        $testTLFilePath = $this->datadir.'/'.self::testTLXMLFileName;
        $lotl->addTrustedListXML(self::testTLName, file_get_contents($testTLFilePath));
        $now = (new DateTime('now'))->format('U');
        $testTL = $lotl->getTrustedLists()[self::testTLName];
        $testTLRefAttributes = self::getTestTLAttributes();
        $testTLTestAttributes = $testTL->getAttributes();
        $this->assertArrayHasKey(
            'signature',
            $testTLTestAttributes['parentTSL']
        );
        $this->assertArrayHasKey(
            'verifiedAt',
            $testTLTestAttributes['parentTSL']['signature']
        );
        $this->assertArrayHasKey(
            'signature',
            $testTLTestAttributes
        );
        $this->assertArrayHasKey(
            'verifiedAt',
            $testTLTestAttributes['signature']
        );
        $this->assertGreaterThan(
            $now - 10,
            $testTLTestAttributes['signature']['verifiedAt']
        );
        $this->assertLessThanOrEqual(
            $now,
            $testTLTestAttributes['signature']['verifiedAt']
        );
        unset($testTLTestAttributes['signature']['verifiedAt']);
        unset($testTLTestAttributes['parentTSL']['signature']['verifiedAt']);
        $this->assertEquals(
            $testTLRefAttributes,
            $testTLTestAttributes
        );
    }
}
