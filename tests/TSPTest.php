<?php

namespace eIDASCertificate\tests;

use PHPUnit\Framework\TestCase;
use eIDASCertificate\DataSource;
use eIDASCertificate\TrustedList;
use eIDASCertificate\Certificate\X509Certificate;
use eIDASCertificate\tests\LOTLRootTest;
use eIDASCertificate\tests\Helper;

class TSPTest extends TestCase
{
    const lotlXMLFileName = 'eu-lotl.xml';
    const testTSPName = 'QuoVadis Trustlink BVBA';

    private $lotlXML;
    private $lotl;
    private $dataDir;

    public function setUp()
    {
        // Helper::getHTTP(TLTest::testTLURI, 'tl');
        // $abc = LOTLRootTest::lotlAttributes;
        // $this->datadir = __DIR__ . '/../data';
        // $xmlFilePath = $this->datadir.'/'.self::lotlXMLFileName;
        // if (! file_exists($xmlFilePath)) {
        //     $this->lotlXML = DataSource::getHTTP(
        //         TrustedList::ListOfTrustedListsXMLPath
        //     );
        //     file_put_contents($xmlFilePath, $this->lotlXML);
        // } else {
        $this->lotlXML = file_get_contents(__DIR__.'/../data/'.self::lotlXMLFileName);
        // }
        $this->lotl = new TrustedList($this->lotlXML);
    }

    public static function getTSPAttributes()
    {
        $tspAttributes = [
          'name' => self::testTSPName,
          'names' => [
            ['lang' => 'en', 'name' => 'QuoVadis Trustlink BVBA'],
          ],
          'tradeNames' => [
            ['lang' => 'en', 'name' => 'VATBE-0537698318'],
            ['lang' => 'en', 'name' => 'QuoVadis'],
          ],
          'trustedList' => TLTest::getTestTLAttributes(),
          'informationURIs' => [
            [
              'lang' => 'en',
              'uri' => 'https://www.quovadisglobal.be/Repository.aspx?sc_lang=en-GB'
            ],
            [
              'lang' => 'fr',
              'uri' => 'https://www.quovadisglobal.be/Repository.aspx?sc_lang=fr-FR'
            ]
          ]
        ];
        return $tspAttributes;
    }

    public function testGetTSPs()
    {
        $lotl = $this->lotl;
        $this->assertEquals(
            0,
            sizeof($lotl->getTSPs(false))
        );
        $this->assertEquals(
            0,
            sizeof($lotl->getTSPs(true))
        );
        $crtFileName = __DIR__.'/../'.LOTLRootTest::lotlSigningCertPath;
        $crt = file_get_contents($crtFileName);
        $rightCert = new X509Certificate(file_get_contents($crtFileName));
        $lotl->verifyTSL($rightCert);
        $testTLFileNAme = __DIR__.'/../'.TLTest::testTLXMLFileName;
        $lotl->addTrustedListXML(TLTest::testTLName, file_get_contents($testTLFileNAme));
        $this->assertEquals(
            1,
            sizeof($lotl->getTrustedLists(false))
        );
        $testTL = $lotl->getTrustedLists()[TLTest::testTLName];
        $this->assertEquals(
            0,
            sizeof($lotl->getTSPs(false))
        );
        $this->assertEquals(
            9,
            sizeof($lotl->getTSPs(true))
        );
        // $this->assertEquals(
        //   [''],
        //   array_keys($lotl->getTSPs(true))
        // );
        $testTSP = $lotl->getTSPs(true)[self::testTSPName];

        $testTSPRefAttributes = self::getTSPAttributes();
        $testTSPTestAttributes = $testTSP->getAttributes();
        $this->assertArrayHasKey(
            'signature',
            $testTSPTestAttributes['trustedList']
        );
        $this->assertArrayHasKey(
            'verifiedAt',
            $testTSPTestAttributes['trustedList']['signature']
        );
        $this->assertArrayHasKey(
            'signature',
            $testTSPTestAttributes['trustedList']['parentTSL']
        );
        $this->assertArrayHasKey(
            'verifiedAt',
            $testTSPTestAttributes['trustedList']['parentTSL']['signature']
        );
        unset($testTSPTestAttributes['trustedList']['signature']['verifiedAt']);
        unset($testTSPTestAttributes['trustedList']['parentTSL']['signature']['verifiedAt']);

        $this->assertEquals(
            $testTSPRefAttributes,
            $testTSPTestAttributes
        );
    }
}
