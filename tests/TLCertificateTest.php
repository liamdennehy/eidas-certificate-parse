<?php

namespace eIDASCertificate\tests;

use PHPUnit\Framework\TestCase;
use eIDASCertificate\DataSource;
use eIDASCertificate\TrustedList;
use eIDASCertificate\Certificate\X509Certificate;

class TLCertificateTest extends TestCase
{
    private $tlolxml;
    public function setUp()
    {
        if (! $this->tlolxml) {
            $this->tlolxml = DataSource::fetch(
                TrustedList::TrustedListOfListsXMLPath
            );
        }
    }

    public function testTLCerts()
    {
        $TrustedListOfLists = new TrustedList($this->tlolxml, null, false);
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
