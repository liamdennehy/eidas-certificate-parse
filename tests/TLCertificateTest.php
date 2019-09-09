<?php

namespace eIDASCertificate\tests;

use PHPUnit\Framework\TestCase;
use eIDASCertificate\DataSource;
use eIDASCertificate\TrustedList;
use eIDASCertificate\Certificate\X509Certificate;

class TLCertificateTest extends TestCase
{
    const lotlXMLFileName = 'eu-lotl.xml';

    private $tlolxml;
    private $dataDir;
    private $lotlXML;

    public function setUp()
    {
        $this->datadir = __DIR__ . '/../data';
        $xmlFilePath = $this->datadir.self::lotlXMLFileName;
        if (! file_exists($xmlFilePath)) {
            $this->lotlXML = DataSource::getHTTP(
                TrustedList::ListOfTrustedListsXMLPath
            );
            file_put_contents($xmlFilePath, $this->lotlXML);
        } else {
            $this->lotlXML = file_get_contents($xmlFilePath);
        }
    }

    public function testTLCerts()
    {
        $TrustedListOfLists = new TrustedList($this->lotlXML, null, false);
        $TLOLCerts = $TrustedListOfLists->getTLX509Certificates();
        foreach ($TLOLCerts as $cert) {
            $this->assertTrue(strlen(X509Certificate::getDN($cert)) > 0);
        };
        $this->assertTrue(true);
        // foreach ($TrustedListOfLists->getTrustedLists() as $tl) {
        //     $tl->verifyTSL();
        //     $TLCert = $tl->getTLX509Certificates()[0];
        //     // $TLSignedByCert = $tl->getSignedBy();
        //     $this->assertTrue(strlen(X509Certificate::getDN($TLCert)) > 0);
        //     // $this->assertTrue(strlen(X509Certificate::getDN($TLSignedByCert)) > 0);
        // }
    }
}
