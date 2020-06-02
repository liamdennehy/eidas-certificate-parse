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

class LOTLRootTest extends TestCase
{
    const lotlXMLFileName = 'eu-lotl.xml';
    const lotlAttributes = [
      'schemeTerritory' => 'EU',
      'schemeOperator' => [
        'name' => 'European Commission',
        'names' => [
          ['lang' => 'en', 'name' => 'European Commission'],
          ['lang' => 'bg', 'name' => 'Европейска комисия'],
          ['lang' => 'es', 'name' => 'Comisión Europea'],
          ['lang' => 'cs', 'name' => 'Evropská komise'],
          ['lang' => 'da', 'name' => 'Europa-Kommissionen'],
          ['lang' => 'de', 'name' => 'Europäische Kommission'],
          ['lang' => 'et', 'name' => 'Euroopa Komisjon'],
          ['lang' => 'el', 'name' => 'Ευρωπαϊκή Επιτροπή'],
          ['lang' => 'fr', 'name' => 'Commission européenne'],
          ['lang' => 'it', 'name' => 'Commissione europea'],
          ['lang' => 'lv', 'name' => 'Eiropas Komisija'],
          ['lang' => 'lt', 'name' => 'Europos Komisija'],
          ['lang' => 'hu', 'name' => 'Európai Bizottság'],
          ['lang' => 'mt', 'name' => 'Il-Kummissjoni Ewropea'],
          ['lang' => 'nl', 'name' => 'Europese Commissie'],
          ['lang' => 'pl', 'name' => 'Komisja Europejska'],
          ['lang' => 'pt', 'name' => 'Comissão Europeia'],
          ['lang' => 'ro', 'name' => 'Comisia Europeană'],
          ['lang' => 'sk', 'name' => 'Európska komisia'],
          ['lang' => 'sl', 'name' => 'Evropska komisija'],
          ['lang' => 'fi', 'name' => 'Euroopan komissio'],
          ['lang' => 'sv', 'name' => 'Europeiska kommissionen'],
          ['lang' => 'hr', 'name' => 'Europska komisija'],
        ],
        'postalAddresses' => [
          [
            'lang' => 'fr',
            'StreetAddress' => 'Rue de la Loi 200',
            'Locality' => 'Bruxelles',
            'PostalCode' => '1049',
            'CountryName' => 'BE'
          ],
          [
            'lang' => 'nl',
            'StreetAddress' => 'Wetstraat 200',
            'Locality' => 'Brussel',
            'PostalCode' => '1049',
            'CountryName' => 'BE'
          ],
          [
            'lang' => 'en',
            'StreetAddress' => 'Rue de la Loi/Wetstraat 200',
            'Locality' => 'Brussels',
            'PostalCode' => '1049',
            'CountryName' => 'BE'
          ],
        ],
        'electronicAddresses' => [
          [
            'lang' => 'en',
            'uri' => 'mailto:EC-TL-Service@ec.europa.eu'
          ],
          [
            'lang' => 'en',
            'uri' => 'https://ec.europa.eu/digital-agenda/en/eu-trusted-lists-certification-service-providers'
          ],
        ]
      ],
      'informationURIs' => [
        ['lang' => 'en','uri' => 'https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=uriserv:OJ.C_.2019.276.01.0001.01.ENG'],
        ['lang' => 'en','uri' => 'https://ec.europa.eu/tools/lotl/eu-lotl-legalnotice.html#en'],
        ['lang' => 'bg','uri' => 'https://ec.europa.eu/tools/lotl/eu-lotl-legalnotice.html#bg'],
        ['lang' => 'es','uri' => 'https://ec.europa.eu/tools/lotl/eu-lotl-legalnotice.html#es'],
        ['lang' => 'cs','uri' => 'https://ec.europa.eu/tools/lotl/eu-lotl-legalnotice.html#cs'],
        ['lang' => 'da','uri' => 'https://ec.europa.eu/tools/lotl/eu-lotl-legalnotice.html#da'],
        ['lang' => 'de','uri' => 'https://ec.europa.eu/tools/lotl/eu-lotl-legalnotice.html#de'],
        ['lang' => 'et','uri' => 'https://ec.europa.eu/tools/lotl/eu-lotl-legalnotice.html#et'],
        ['lang' => 'el','uri' => 'https://ec.europa.eu/tools/lotl/eu-lotl-legalnotice.html#el'],
        ['lang' => 'fr','uri' => 'https://ec.europa.eu/tools/lotl/eu-lotl-legalnotice.html#fr'],
        ['lang' => 'it','uri' => 'https://ec.europa.eu/tools/lotl/eu-lotl-legalnotice.html#it'],
        ['lang' => 'lv','uri' => 'https://ec.europa.eu/tools/lotl/eu-lotl-legalnotice.html#lv'],
        ['lang' => 'lt','uri' => 'https://ec.europa.eu/tools/lotl/eu-lotl-legalnotice.html#lt'],
        ['lang' => 'hu','uri' => 'https://ec.europa.eu/tools/lotl/eu-lotl-legalnotice.html#hu'],
        ['lang' => 'mt','uri' => 'https://ec.europa.eu/tools/lotl/eu-lotl-legalnotice.html#mt'],
        ['lang' => 'nl','uri' => 'https://ec.europa.eu/tools/lotl/eu-lotl-legalnotice.html#nl'],
        ['lang' => 'pl','uri' => 'https://ec.europa.eu/tools/lotl/eu-lotl-legalnotice.html#pl'],
        ['lang' => 'pt','uri' => 'https://ec.europa.eu/tools/lotl/eu-lotl-legalnotice.html#pt'],
        ['lang' => 'ro','uri' => 'https://ec.europa.eu/tools/lotl/eu-lotl-legalnotice.html#ro'],
        ['lang' => 'sk','uri' => 'https://ec.europa.eu/tools/lotl/eu-lotl-legalnotice.html#sk'],
        ['lang' => 'sl','uri' => 'https://ec.europa.eu/tools/lotl/eu-lotl-legalnotice.html#sl'],
        ['lang' => 'fi','uri' => 'https://ec.europa.eu/tools/lotl/eu-lotl-legalnotice.html#fi'],
        ['lang' => 'sv','uri' => 'https://ec.europa.eu/tools/lotl/eu-lotl-legalnotice.html#sv'],
        ['lang' => 'hr','uri' => 'https://ec.europa.eu/tools/lotl/eu-lotl-legalnotice.html#hr'],
      ],
      'sequenceNumber' => 266,
      'sourceURI' => 'https://ec.europa.eu/tools/lotl/eu-lotl.xml',
      'issued' => '1590487200',
      'nextUpdate' => '1606348800',
      'fileHash' => 'b3030a0d729e6bfefc18d4c7d0a3f0bce90528057ebed63e06d140dd2d1100d9',
      'signature' => [
        'signerThumbprint' => '8e508f03b132500c3403db66e9dd39cd78f4657c840958a77d34e7bd621468e7'
      ]
    ];
    const lotlSigningCertPath =
      'data/journal/c-276-1/8e508f03b132500c3403db66e9dd39cd78f4657c840958a77d34e7bd621468e7.crt';
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
        $rightCertHash = '8e508f03b132500c3403db66e9dd39cd78f4657c840958a77d34e7bd621468e7';
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
                'signedBy' => '8e508f03b132500c3403db66e9dd39cd78f4657c840958a77d34e7bd621468e7',
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
            '8e508f03b132500c3403db66e9dd39cd78f4657c840958a77d34e7bd621468e7',
            $lotl->getSignedBy()->getIdentifier()
        );

        $lotlSignedByDN = $lotl->getSignedBy()->getSubjectDN();
        $this->assertEquals(
            '/emailAddress=adrian.croitoru@ec.europa.eu/C=RO/L=BE'.
            '/O=European Commission/OU=0949.383.342'.
            '/CN=Constantin-Adrian Croitoru/SN=Croitoru/GN=Constantin-Adrian'.
            '/serialNumber=10304387540106101740/title=Professional Person',
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
        $crtFileName = $this->datadir.'/journal/c-276-1/8e508f03b132500c3403db66e9dd39cd78f4657c840958a77d34e7bd621468e7.crt';
        $crt = file_get_contents($crtFileName);
        $rightCert = new X509Certificate(file_get_contents($crtFileName));
        $this->assertTrue($lotl->verifyTSL($rightCert));
        $now = (new DateTime('now'))->format('U');
        $this->assertEquals(
            '8e508f03b132500c3403db66e9dd39cd78f4657c840958a77d34e7bd621468e7',
            $lotl->getSignedByHash()
        );
        // TODO: Handle bad TL Admins and distributions

        // foreach ($lotl->getTLPointerPaths() as $title => $tlPointer) {
        //     $localFile = $this->datadir.'/tl-'.$tlPointer['id'].'.xml';
        //     if (file_exists($localFile)) {
        //         $pointedTLs[$title]['xml'] = file_get_contents($localFile);
        //     } else {
        //         $pointedTLs[$title]['xml'] = DataSource::getHTTP($tlPointer['location']);
        //         file_put_contents($localFile, $pointedTLs[$title]['xml']);
        //     }
        //     try {
        //         $schemeOperatorName =
        //             $lotl->addTrustedListXML($title, $pointedTLs[$title]['xml']);
        //         // It seems that some ScheOperatorNames can differ between
        //         // LOTL and country TL
        //         $verifiedTLs[] = $schemeOperatorName;
        //     } catch (ParseException $e) {
        //         if ($e->getMessage() == 'No input XML string found for new TrustedList') {
        //             throw new ParseException("Empty XML: ".$title, 1);
        //         } else {
        //             throw $e;
        //         }
        //     } catch (SignatureException $e) {
        //         $unVerifiedTLs[] = $title;
        //     }
        // }
        // $this->assertEquals(
        //     0, // Bad player?
        //   sizeof($unVerifiedTLs)
        // );
        // $this->assertEquals(
        //     sizeof($verifiedTLs),
        //     sizeof($lotl->getTrustedLists(true))
        // );
        // $lotlRefAttributes = self::getLOTLAttributes();
        // $lotlTestAttributes = $lotl->getAttributes();
        // $this->assertArrayHasKey(
        //     'signature',
        //     $lotlTestAttributes
        // );
        // $this->assertArrayHasKey(
        //     'verifiedAt',
        //     $lotlTestAttributes['signature']
        // );
        // $this->assertGreaterThan(
        //     $now - 10,
        //     $lotlTestAttributes['signature']['verifiedAt']
        // );
        // $this->assertLessthanOrEqual(
        //     $now,
        //     $lotlTestAttributes['signature']['verifiedAt']
        // );
        // unset($lotlTestAttributes['signature']['verifiedAt']);
        // $this->assertEquals(
        //     $lotlRefAttributes,
        //     $lotlTestAttributes
        // );
    }
}
