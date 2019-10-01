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
        Helper::getHTTP(TLTest::testTLURI, 'tl');
        $abc = LOTLRootTest::lotlAttributes;
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
    }

    public static function getTSPAttributes()
    {
        $tspAttributes['name'] = self::testTSPName;
        $tspAttributes['trustedList'] = TLTest::getTestTLAttributes();
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
        $crtFileName = $this->datadir.LOTLRootTest::lotlSigningCertPath;
        $crt = file_get_contents($crtFileName);
        $rightCert = new X509Certificate(file_get_contents($crtFileName));
        $lotl->verifyTSL($rightCert);
        $testTLFileNAme = $this->datadir.'/'.TLTest::testTLXMLFileName;
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
        $testTSPTestAttributes = $testTSP->getTSPAttributes();
        $this->assertArrayHasKey(
            'tslSignatureVerifiedAt',
            $testTSPTestAttributes['trustedList']
        );
        $this->assertArrayHasKey(
            'tslSignatureVerifiedAt',
            $testTSPTestAttributes['trustedList']['parentTSL']
        );
        unset($testTSPTestAttributes['trustedList']['tslSignatureVerifiedAt']);
        unset($testTSPTestAttributes['trustedList']['parentTSL']['tslSignatureVerifiedAt']);

        $this->assertEquals(
            $testTSPRefAttributes,
            $testTSPTestAttributes
        );
    }
}
