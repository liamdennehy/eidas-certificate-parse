<?php

namespace eIDASCertificate\tests;

use PHPUnit\Framework\TestCase;
use eIDASCertificate\DataSource;
use eIDASCertificate\TrustedList;
use eIDASCertificate\TSPService;
use eIDASCertificate\Certificate\X509Certificate;
use eIDASCertificate\ParseException;
use eIDASCertificate\SignatureException;
use eIDASCertificate\CertificateException;
use eIDASCertificate\TrustedListException;
use eIDASCertificate\tests\Helper;

class TSPServicesTest extends TestCase
{
    const lotlXMLFileName = 'eu-lotl.xml';
    const TSPServiceCertHash = 'd90b40132306d1094608b1b9a2f6a9e23b45fe121fef514a1c9df70a815ad95c';
    const testTSPServiceName = 'QuoVadis BE PKI Certification Authority G2';
    const testTSPServiceCertFile = 'qvbecag2.crt';
    private $lotlxml;
    private $lotl;
    private $datadir;

    public function setUp()
    {
        Helper::getHTTP(TLTest::testTLURI, 'tl');
        $this->datadir = __DIR__ . '/../data/';
        $xmlFilePath = $this->datadir.self::lotlXMLFileName;
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

    public static function getTSPServiceAttributes()
    {
        $attributes = [
          'name' => self::testTSPServiceName,
          'type' => 'CA/QC',
          'status' => 'granted',
          'isActive' => true,
          'isQualified' => true,
          'statusStartingTime' => 1518048000,
          'certificates' => [
            self::TSPServiceCertHash =>
              file_get_contents(__DIR__.'/certs/'.self::testTSPServiceCertFile)
          ],
          'skiBase64' => 'h8m8MZcSenO7fsA9RVG0ASWVUas=',
          'skiHex' => '87c9bc3197127a73bb7ec03d4551b401259551ab',
          'subjectName' => 'CN=QuoVadis Belgium Issuing CA G2, O=QuoVadis Trustlink BVBA, OID.2.5.4.97=NTRBE-0537698318, C=BE',
          'serviceHistory' => [
            [1518048000, 'granted'],
            [1467324000, 'granted'],
            [1465776000, 'undersupervision']
          ]
        ];
        $attributes['trustServiceProvider'] =  TSPTest::getTSPAttributes();
        return $attributes;
    }

    public function testGetTSPServices()
    {
        $lotl = $this->lotl;
        $crtFileName = $this->datadir.LOTLRootTest::lotlSigningCertPath;
        $crt = file_get_contents($crtFileName);
        $rightCert = new X509Certificate(file_get_contents($crtFileName));
        $lotl->verifyTSL($rightCert);
        $testTLFilePath = $this->datadir.TLTest::testTLXMLFileName;
        $this->lotl->addTrustedListXML(TLTest::testTLName, file_get_contents($testTLFilePath));
        $testTL = $lotl->getTrustedLists()[TLTest::testTLName];
        $tspServices = $lotl->getTSPServices(true);
        $this->assertEquals(
            3,
            sizeof($testTL->getTSPs()[TSPTest::testTSPName]->getTSPServices())
        );
        $refAttributes = self::getTSPServiceAttributes();
        $testAttributes = $tspServices[self::testTSPServiceName];
        $this->assertArrayHasKey(
            'tslSignatureVerifiedAt',
            $testAttributes['trustServiceProvider']['trustedList']
        );
        $this->assertArrayHasKey(
            'tslSignatureVerifiedAt',
            $testAttributes['trustServiceProvider']['trustedList']['parentTSL']
        );
        unset($testAttributes['trustServiceProvider']['trustedList']['tslSignatureVerifiedAt']);
        unset($testAttributes['trustServiceProvider']['trustedList']['parentTSL']['tslSignatureVerifiedAt']);
        $this->assertEquals(
            $refAttributes,
            $testAttributes
        );
        $this->assertTrue(is_array($tspServices));
        $this->assertGreaterThan(0, sizeof($tspServices));
    }
}
