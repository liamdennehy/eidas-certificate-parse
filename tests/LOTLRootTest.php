<?php

namespace eIDASCertificate\tests;

use PHPUnit\Framework\TestCase;
use eIDASCertificate\DataSource;
use eIDASCertificate\TrustedList;
use eIDASCertificate\Certificate\X509Certificate;
use eIDASCertificate\ParseException;
use eIDASCertificate\SignatureException;
use eIDASCertificate\CertificateException;
use eIDASCertificate\TrustedListException;
use DateTime;
use eIDASCertificate\tests\Helper;

class LOTLRootTest extends TestCase
{
    const lotlXMLFileName = 'eu-lotl.xml';
    const lotlAttributes = [
      'schemeTerritory' => 'EU',
      'schemeOperatorName' => 'European Commission',
      'tslSequenceNumber' => 250,
      'tslSignedByHash' => 'd2064fdd70f6982dcc516b86d9d5c56aea939417c624b2e478c0b29de54f8474',
      'sourceURI' => 'https://ec.europa.eu/tools/lotl/eu-lotl.xml'
    ];
    const lotlSigningCertPath =
      '/journal/c-276-1/d2064fdd70f6982dcc516b86d9d5c56aea939417c624b2e478c0b29de54f8474.crt';
    const lotlHash =
      '56bbdeb154d25bfc735bda4f958fead0b578712f79037227f87d2ad7bcf7880d';
    private $lotlxml;
    private $lotl;
    private $datadir;

    public static function getLOTLAttributes()
    {
        $attributes = self::lotlAttributes;
        return $attributes;
    }

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
    }

    public function testParseLOTL()
    {
        $this->lotl = new TrustedList($this->lotlXML);
        $this->assertEquals(
            "EUlistofthelists",
            $this->lotl->getTSLType()->getType()
        );
        $this->assertEquals(
            self::lotlHash,
            $this->lotl->getXMLHash()
        );
        $this->assertInternalType("int", $this->lotl->getVersionID());
        $this->assertInternalType("int", $this->lotl->getSequenceNumber());
        $this->assertEquals(
            5,
            $this->lotl->getVersionID()
        );
        $this->assertGreaterThan(
            1,
            $this->lotl->getSequenceNumber()
        );

        $this->assertGreaterThan(
            0,
            sizeof($this->lotl->getTLX509Certificates())
        );
        foreach ($this->lotl->getTLX509Certificates() as $lotlCert) {
            $this->assertGreaterThan(
                20,
                strlen($lotlCert->getSubjectDN())
            );
        }
    }

    // public function testVerifyLOTLSelfSignedFails()
    // {
    //     $lotl = new TrustedList($this->lotlXML);
    //     $this->expectException(CertificateException::class);
    //     $lotl->verifyTSL();
    // }

    public function testVerifyLOTLExplicitSigned()
    {
        $wrongCertHash = '9c1a3b646eaf132398ef319e41c8e7ed725b64d5772580ae125d59c0f6845630';
        $rightCertHash = 'd2064fdd70f6982dcc516b86d9d5c56aea939417c624b2e478c0b29de54f8474';
        $certpaths = scandir($this->datadir.'/journal/c-276-1');
        while ($certpaths[0] == '.' || $certpaths[0] == '..') {
            array_shift($certpaths);
        }
        $certs = [];
        foreach ($certpaths as $certpath) {
            $id = explode('.', $certpath)[0];
            $certs[$id] = file_get_contents($this->datadir.'/journal/c-276-1/'.$certpath);
        }
        $wrongCert = new X509Certificate($certs[$wrongCertHash]);
        $rightCert = new X509Certificate($certs[$rightCertHash]);
        $lotl = new TrustedList($this->lotlXML);
        try {
            $lotl->verifyTSL([$wrongCert]);
            $this->assetTrue(false); // Should never hit this if exception is raised
        } catch (SignatureException $e) {
            $this->assertEquals(
                [
                'signedBy' => 'd2064fdd70f6982dcc516b86d9d5c56aea939417c624b2e478c0b29de54f8474',
                'availableCerts' => [
                  '9c1a3b646eaf132398ef319e41c8e7ed725b64d5772580ae125d59c0f6845630'
                ]
              ],
                $e->getOut()
            );
        }
        $lotl = new TrustedList($this->lotlXML);
        $this->assertTrue($lotl->verifyTSL([$wrongCert,$rightCert]));
        $lotl = new TrustedList($this->lotlXML);
        $this->assertTrue($lotl->verifyTSL($rightCert));
        $this->assertEquals(
            'd2064fdd70f6982dcc516b86d9d5c56aea939417c624b2e478c0b29de54f8474',
            $lotl->getSignedBy()->getIdentifier()
        );

        $lotlSignedByDN = $lotl->getSignedBy()->getSubjectDN();
        $this->assertEquals(
            '/C=BE/CN=Patrick Kremer (Signature)/SN=Kremer/givenName=Patrick Jean/serialNumber=72020329970',
            $lotlSignedByDN
        );
    }

    public function testGetLOTLTrustedListXMLPointers()
    {
        $lotl = new TrustedList($this->lotlXML);
        $validURLFilterFlags =
            FILTER_FLAG_PATH_REQUIRED;
        $tlXMLPointers = $lotl->getTrustedListPointers('xml');
        $this->assertGreaterThan(
            12,
            sizeof($tlXMLPointers)
        );
        foreach ($tlXMLPointers as $tlPointer) {
            $this->assertEquals(
                "application/vnd.etsi.tsl+xml",
                $tlPointer->getTSLMimeType()
            );
            $dp = $tlPointer->getTSLLocation();
            $this->assertEquals(
                $dp,
                filter_var(
                    $dp,
                    FILTER_VALIDATE_URL,
                    $validURLFilterFlags
                )
            );
        };
    }

    public function testTLOLVerifyFailsWithoutTLs()
    {
        $lotl = new TrustedList($this->lotlXML);
        try {
            $lotl->verifyAllTLs();
            $this->assetTrue(false); //Should never get here
        } catch (TrustedListException $e) {
            $this->assertEquals(
                'No TrustedLists provided',
                $e->getMessage()
            );
        };
        return;
        $this->assertFalse(true); // Only the right exception was thrown
    }

    public function testAddTLstoLOTL()
    {
        $verifiedTLs = [];
        $unVerifiedTLs = [];
        $lotl = new TrustedList($this->lotlXML);
        $this->assertEquals(
            0,
            sizeof($lotl->getTrustedLists(true))
        );

        $pointedTLs = [];
        $crtFileName = $this->datadir.'/journal/c-276-1/d2064fdd70f6982dcc516b86d9d5c56aea939417c624b2e478c0b29de54f8474.crt';
        $crt = file_get_contents($crtFileName);
        $rightCert = new X509Certificate(file_get_contents($crtFileName));
        $this->assertTrue($lotl->verifyTSL($rightCert));
        $now = (new DateTime('now'))->format('U');
        $this->assertEquals(
            'd2064fdd70f6982dcc516b86d9d5c56aea939417c624b2e478c0b29de54f8474',
            $lotl->getSignedByHash()
        );
        foreach ($lotl->getTLPointerPaths() as $title => $tlPointer) {
            $localFile = $this->datadir.'/tl-'.$tlPointer['id'].'.xml';
            if (file_exists($localFile)) {
                $pointedTLs[$title]['xml'] = file_get_contents($localFile);
            } else {
                $pointedTLs[$title]['xml'] = DataSource::getHTTP($tlPointer['location']);
                file_put_contents($localFile, $pointedTLs[$title]['xml']);
            }
            try {
                $schemeOperatorName =
                    $lotl->addTrustedListXML($title, $pointedTLs[$title]['xml']);
                // It seems that some ScheOperatorNames can differ between
                // LOTL and country TL
                $verifiedTLs[] = $schemeOperatorName;
            } catch (ParseException $e) {
                if ($e->getMessage() == 'No input XML string found for new TrustedList') {
                    throw new ParseException("Empty XML: ".$title, 1);
                } else {
                    throw $e;
                }
            } catch (SignatureException $e) {
                $unVerifiedTLs[] = $title;
            }
        }
        $this->assertEquals(
            0, // Bad player?
          sizeof($unVerifiedTLs)
        );
        $this->assertEquals(
            sizeof($verifiedTLs),
            sizeof($lotl->getTrustedLists(true))
        );
        $lotlRefAttributes = self::getLOTLAttributes();
        $lotlTestAttributes = $lotl->getAttributes();
        $this->assertArrayHasKey(
            'tslSignatureVerifiedAt',
            $lotlTestAttributes
        );
        $this->assertGreaterThan(
            $now - 10,
            $lotlTestAttributes['tslSignatureVerifiedAt']
        );
        $this->assertLessthanOrEqual(
            $now,
            $lotlTestAttributes['tslSignatureVerifiedAt']
        );
        unset($lotlTestAttributes['tslSignatureVerifiedAt']);
        $this->assertEquals(
            $lotlRefAttributes,
            $lotlTestAttributes
        );
    }
}
