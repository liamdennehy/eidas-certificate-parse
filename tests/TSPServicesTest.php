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
    const EUTSPServiceCertHash = 'd90b40132306d1094608b1b9a2f6a9e23b45fe121fef514a1c9df70a815ad95c';
    const EUTSPServiceName = 'QuoVadis BE PKI Certification Authority G2';
    const EUTSPServiceCertFile = 'qvbecag2.crt';
    const TSPServiceCertHash = 'f640e5643c40c1f329e100438e28c957691afa8a53e405a326f7afeb70c23bc1';
    const testTSPServiceName = 'itsme Sign Issuing CA G1';
    const testTSPServiceCertFile = 'itsme-Sign-Issuing-G1.crt';
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

    public static function getTestTSPServiceAttributes()
    {
        $attributes = [
          'name' => self::testTSPServiceName,
          'type' => 'CA/QC',
          'status' => 'granted',
          'isActive' => true,
          'isQualified' => true,
          'statusStartingTime' => 1552003200,
          'x509Certificates' => [
            [
              'id' => self::TSPServiceCertHash,
              'PEM' => file_get_contents(__DIR__.'/certs/'.self::testTSPServiceCertFile)
            ]
          ],
          'skiBase64' => 'jUsZwqAowXDYwGegmOKna0nSq6c=',
          'skiHex' => '8d4b19c2a028c170d8c067a098e2a76b49d2aba7',
          'subjectName' => 'CN=itsme Sign Issuing CA G1, O=QuoVadis Trustlink BVBA, OID.2.5.4.97=NTRBE-0537698318, C=BE',
          'serviceHistory' => [
            [
              'statusStartingTime' => 1552003200,
              'status' =>'granted'
            ],
          ],
          'qualifierURIs' => [
            'http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/QCQSCDManagedOnBehalf',
            'http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/NotQualified'
          ]
        ];
        $attributes['trustServiceProvider'] =  TSPTest::getTSPAttributes();
        return $attributes;
    }

    public static function getEUTSPServiceAttributes()
    {
        $attributes = [
          'name' => self::EUTSPServiceName,
          'type' => 'CA/QC',
          'status' => 'granted',
          'isActive' => true,
          'isQualified' => true,
          'statusStartingTime' => 1518048000,
          'x509Certificates' => [
            [
              'id' => self::EUTSPServiceCertHash,
              'PEM' => file_get_contents(__DIR__.'/certs/'.self::EUTSPServiceCertFile)
            ]
          ],
          'skiBase64' => 'h8m8MZcSenO7fsA9RVG0ASWVUas=',
          'skiHex' => '87c9bc3197127a73bb7ec03d4551b401259551ab',
          'subjectName' => 'CN=QuoVadis Belgium Issuing CA G2, O=QuoVadis Trustlink BVBA, OID.2.5.4.97=NTRBE-0537698318, C=BE',
          'serviceHistory' => [
            [
              'statusStartingTime' => 1518048000,
              'status' => 'granted',
              'serviceType' => 'CA/QC'
            ],
            [
              'statusStartingTime' => 1467324000,
              'status' => 'granted',
              'serviceType' => 'CA/QC'
            ],
            [
              'statusStartingTime' => 1465776000,
              'status' => 'undersupervision',
              'serviceType' => 'CA/QC',
            ],
          ],
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
        // var_dump(array_keys($testTL->getTSPs())); exit;
        $this->assertEquals(
            3,
            sizeof($testTL->getTSPs()[TSPTest::testTSPName]->getTSPServices())
        );
        $refAttributes = self::getTestTSPServiceAttributes();
        $testAttributes = $tspServices[self::testTSPServiceName];
        $this->assertArrayHasKey(
            'signature',
            $testAttributes['trustServiceProvider']['trustedList']
        );
        $this->assertArrayHasKey(
            'verifiedAt',
            $testAttributes['trustServiceProvider']['trustedList']['signature']
        );
        $this->assertArrayHasKey(
            'signature',
            $testAttributes['trustServiceProvider']['trustedList']['parentTSL']
        );
        $this->assertArrayHasKey(
            'verifiedAt',
            $testAttributes['trustServiceProvider']['trustedList']['parentTSL']['signature']
        );
        unset($testAttributes['trustServiceProvider']['trustedList']['signature']['verifiedAt']);
        unset($testAttributes['trustServiceProvider']['trustedList']['parentTSL']['signature']['verifiedAt']);
        $this->assertEquals(
            $refAttributes,
            $testAttributes
        );
        $this->assertTrue(is_array($tspServices));
        $this->assertGreaterThan(0, sizeof($tspServices));
    }
}
