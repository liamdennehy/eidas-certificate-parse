<?php

namespace eIDASCertificate\tests;

use PHPUnit\Framework\TestCase;
use eIDASCertificate\DataSource;
use eIDASCertificate\TrustedList;
use eIDASCertificate\Certificate\X509Certificate;
use eIDASCertificate\tests\LOTLRootTest;

class TSPTest extends TestCase
{
    const lotlXMLFileName = 'eu-lotl.xml';

    private $lotlXML;
    private $lotl;
    private $tls;
    private $dataSource;
    private $dataDir;

    public function setUp()
    {
        $abc = LOTLRootTest::lotlAttributes;
        $this->datadir = __DIR__ . '/../data';
        $xmlFilePath = $this->datadir.'/'.self::lotlXMLFileName;
        if (! file_exists($xmlFilePath)) {
            $lotlXML = DataSource::getHTTP(
                TrustedList::ListOfTrustedListsXMLPath
            );
            file_put_contents($xmlFilePath, $this->lotlXML);
        } else {
            $lotlXML = file_get_contents($xmlFilePath);
        }
        $this->lotl = new TrustedList($lotlXML);
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
        $crtFileName = $this->datadir.'/journal/c-276-1/d2064fdd70f6982dcc516b86d9d5c56aea939417c624b2e478c0b29de54f8474.crt';
        $crt = file_get_contents($crtFileName);
        $rightCert = new X509Certificate(file_get_contents($crtFileName));
        $lotl->verifyTSL($rightCert);
        $nlFile = $this->datadir.'/tl-52f7b34b484ce888c5f1d277bcb2bfbff0b1d3bbf11217a44090fab4b6a83fd3.xml';
        $lotl->addTrustedListXML("NL: Radiocommunications Agency", file_get_contents($nlFile));
        $this->assertEquals(
            1,
            sizeof($lotl->getTrustedLists(false))
        );
        $nlTL = $lotl->getTrustedLists()["NL: Radiocommunications Agency"];
        $this->assertGreaterThan(
            0,
            sizeof($nlTL->getTSPs(false))
        );
        $this->assertEquals(
            0,
            sizeof($lotl->getTSPs(false))
        );
        $this->assertEquals(
            11,
            sizeof($lotl->getTSPs(true))
        );
        $digidentityBV = $lotl->getTSPs(true)['Digidentity B.V.'];
        $nlAttributes = TLTest::getNLTLAttributes();
        $nlAttributes['ParentTSL'] = LOTLRootTest::lotlAttributes;
        $this->assertEquals(
            [
            'ParentTSL' => $nlAttributes,
            'TrustServiceProvider' => 'Digidentity B.V.'
          ],
            $digidentityBV->getTSPAtrributes()
        );
        $tsps = $this->lotl->getTSPs(true);
    }
}
