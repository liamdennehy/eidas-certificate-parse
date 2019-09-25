<?php

namespace eIDASCertificate\tests;

use PHPUnit\Framework\TestCase;
use eIDASCertificate\DataSource;
use eIDASCertificate\TrustedList;
use eIDASCertificate\Certificate\X509Certificate;

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
        $this->datadir = __DIR__ . '/../data';
        $xmlFilePath = $this->datadir.self::lotlXMLFileName;
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
        $nlFile = $this->datadir.'/tl-52f7b34b484ce888c5f1d277bcb2bfbff0b1d3bbf11217a44090fab4b6a83fd3.xml';
        $this->lotl->addTrustedListXML("NL: Radiocommunications Agency", file_get_contents($nlFile));
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
        $this->assertGreaterThan(
            0,
            sizeof($lotl->getTSPs(true))
        );

        $tsps = $this->lotl->getTSPs(true);
    }
}
