<?php

namespace eIDASCertificate\tests;

use PHPUnit\Framework\TestCase;
use eIDASCertificate\Certificate\X509Certificate;
use eIDASCertificate\TrustedList;
use ASN1\Type\UnspecifiedType;

class CertificateParseTest extends TestCase
{
    const jmcrtfile = 'Jean-Marc Verbergt (Signature).crt';
    const mocrtfile = 'Maarten Joris Ottoy.crt';
    const eucrtfile = 'European-Commission.crt';
    const euissuercrtfile = 'qvbecag2.crt';
    const euIssuercertId = 'd90b40132306d1094608b1b9a2f6a9e23b45fe121fef514a1c9df70a815ad95c';
    const lotlSignerHash = 'd2064fdd70f6982dcc516b86d9d5c56aea939417c624b2e478c0b29de54f8474';

    public function setUp()
    {
        $this->testTime = new \DateTime('@1569225604');
        $this->eucrtSubject = [
          [
            'oid' => 'countryName (2.5.4.6)',
            'value' => 'BE'
          ],
          [
            'oid' => 'organizationalUnitName (2.5.4.11)',
            'value' => 'DG CONNECT'
          ],
          [
            'oid' => 'organizationIdentifier (2.5.4.97)',
            'value' => 'VATBE-0949.383.342'
          ],
          [
            'oid' => 'organizationName (2.5.4.10)',
            'value' => 'European Commission'
          ],
          [
            'oid' => 'commonName (2.5.4.3)',
            'value' => 'EC_CNECT'
          ]
        ];
        $this->eucrtIssuerSubject = [
          [
            'oid' => 'countryName (2.5.4.6)',
            'value' => 'BE'
          ],
          [
            'oid' => 'organizationIdentifier (2.5.4.97)',
            'value' => 'NTRBE-0537698318'
          ],
          [
            'oid' => 'organizationName (2.5.4.10)',
            'value' => 'QuoVadis Trustlink BVBA'
          ],
          [
            'oid' => 'commonName (2.5.4.3)',
            'value' => 'QuoVadis Belgium Issuing CA G2'
          ],
        ];
        $this->eucrtAttributes =
        [
          'subjectDN' => '/C=BE/OU=DG CONNECT/2.5.4.97=VATBE-0949.383.342/O=European Commission/CN=EC_CNECT',
          'issuerDN' => 'C=BE/UNDEF=NTRBE-0537698318/O=QuoVadis Trustlink BVBA/CN=QuoVadis Belgium Issuing CA G2',
          'fingerprint' => 'ccd879b36bb553685becbd12901c7f41f7bd3e07f898fcbbe1eec456b03d7589',
          'skiHex' => 'e811fc46be23b48f3ef7b1d778df0997b8ec4524',
          'skiBase64' => '6BH8Rr4jtI8+97HXeN8Jl7jsRSQ=',
          'akiHex' => '87c9bc3197127a73bb7ec03d4551b401259551ab',
          'akiBase64' => 'h8m8MZcSenO7fsA9RVG0ASWVUas=',
          'subjectExpanded' => $this->eucrtSubject,
          'issuerExpanded' => $this->eucrtIssuerSubject
        ];
        $this->euIssuercrtIssuerAttributes = [
          [
            'oid' => 'countryName (2.5.4.6)',
            'value' => 'BM'
          ],
          [
            'oid' => 'organizationName (2.5.4.10)',
            'value' => 'QuoVadis Limited'
          ],
          [
            'oid' => 'commonName (2.5.4.3)',
            'value' => 'QuoVadis Enterprise Trust CA 1 G3'
          ]
        ];

        $this->euIssuercrtAttributes =
        [
          'subjectDN' => '/C=BE/2.5.4.97=NTRBE-0537698318/O=QuoVadis Trustlink BVBA/CN=QuoVadis Belgium Issuing CA G2',
          'issuerDN' => 'C=BM/O=QuoVadis Limited/CN=QuoVadis Enterprise Trust CA 1 G3',
          'fingerprint' => 'd90b40132306d1094608b1b9a2f6a9e23b45fe121fef514a1c9df70a815ad95c',
          'skiHex' => '87c9bc3197127a73bb7ec03d4551b401259551ab',
          'skiBase64' => 'h8m8MZcSenO7fsA9RVG0ASWVUas=',
          'akiHex' => '6c26bd605529294e663207a0ff638b835a4b34c6',
          'akiBase64' => 'bCa9YFUpKU5mMgeg/2OLg1pLNMY=',
          'subjectExpanded' => $this->eucrtIssuerSubject,
          'issuerExpanded' => $this->euIssuercrtIssuerAttributes
        ];
        $this->euIssuerCrtId = 'd90b40132306d1094608b1b9a2f6a9e23b45fe121fef514a1c9df70a815ad95c';
    }
    public function getTestCerts()
    {
        $this->jmcrt = new X509Certificate(
            file_get_contents(
                __DIR__ . "/certs/" . self::jmcrtfile
            )
        );
        $this->mocrt = new X509Certificate(
            file_get_contents(
                __DIR__ . "/certs/" . self::mocrtfile
            )
        );
        $this->eucrt = new X509Certificate(
            file_get_contents(
                __DIR__ . "/certs/" . self::eucrtfile
            )
        );
        $this->euissuercrt =
            file_get_contents(
                __DIR__ . "/certs/" . self::euissuercrtfile
            );
    }

    public function testX509Parse()
    {
        $PEM = file(__DIR__ . "/certs/" . self::jmcrtfile);
        array_shift($PEM);
        unset($PEM[sizeof($PEM)]);
        $DER = base64_decode(implode('', $PEM));
        $crtFromDER = new X509Certificate($DER);
        $this->getTestCerts();
        $crtParsed = $this->eucrt->getParsed();
        $this->assertEquals(
            '/C=BE/OU=DG CONNECT/2.5.4.97=VATBE-0949.383.342'.
            '/O=European Commission/CN=EC_CNECT',
            $crtParsed['name']
        );
        $this->assertTrue($this->eucrt->hasExtensions()) ;
        $this->assertTrue($this->eucrt->hasQCStatements()) ;
        $this->assertEquals(
            [
              'http://crl.quovadisglobal.com/qvbecag2.crl'
            ],
            $this->eucrt->getCDPs()
        );
        $this->assertEquals(
            [
              '87c9bc3197127a73bb7ec03d4551b401259551ab',
              'e811fc46be23b48f3ef7b1d778df0997b8ec4524',
              'e811fc46be23b48f3ef7b1d778df0997b8ec4524'
            ],
            [
              bin2hex($this->eucrt->getAuthorityKeyIdentifier()),
              bin2hex($this->eucrt->getSubjectKeyIdentifier()),
              hash('sha1', UnspecifiedType::fromDER($this->eucrt->getPublicKey())->asSequence()->at(1)->asBitString()->string())
            ]
        );
        $this->assertTrue($this->eucrt->hasExtensions());
        $this->assertEquals(
            [
              'authorityInfoAccess',
              'subjectKeyIdentifier',
              'authorityKeyIdentifier',
              'crlDistributionPoints',
              'keyUsage',
              'extKeyUsage',
              'unknown-1.2.840.113583.1.1.9.2',
              'unknown-1.2.840.113583.1.1.9.1',
              'qcStatements'
            ],
            $this->eucrt->getExtensionNames()
        );
        $this->assertTrue($this->eucrt->hasQCStatements());
        $this->assertEquals(
            [
              'QCSyntaxV2',
              'QCCompliance',
              'QCSSCD',
              'QCQualifiedType',
              'QCPDS'
            ],
            $this->eucrt->getQCStatementNames()
        );
        $crtParsed = $this->mocrt->getParsed();
        $this->assertEquals(
            '/C=BE/L=BE/O=European Commission/OU=0949.383.342'.
            '/CN=Maarten Joris Ottoy/SN=Ottoy/GN=Maarten Joris'.
            '/serialNumber=10304444110080837592'.
            '/emailAddress=maarten.ottoy@ec.europa.eu'.
            '/title=Professional Person',
            $crtParsed['name']
        );
        $this->assertEquals(
            [
              'C' => 'BE',
              'L' => 'BE',
              'O' => 'European Commission',
              'OU' => '0949.383.342',
              'CN' => 'Maarten Joris Ottoy',
              'SN' => 'Ottoy',
              'GN' => 'Maarten Joris',
              'serialNumber' => '10304444110080837592',
              'emailAddress' => 'maarten.ottoy@ec.europa.eu',
              'title' => 'Professional Person'
            ],
            $crtParsed['subject']
        );
        $this->assertEquals(
            [
              '638fc28b03b1ab8ed85347961d99a87df6aca875',
              '47c3b10901b1822b'
            ],
            [
              bin2hex($this->mocrt->getAuthorityKeyIdentifier()),
              bin2hex($this->mocrt->getSubjectKeyIdentifier())
            ]
        );
        $this->assertEquals(
            [
              'http://crl.quovadisglobal.com/qvbecag2.crl'
            ],
            $this->eucrt->getCDPs()
        );
        $crtParsed = $this->jmcrt->getParsed();
        $this->assertEquals(
            '/C=BE/CN=Jean-Marc Verbergt (Signature)/SN=Verbergt/GN=Jean-Marc/serialNumber=67022330340',
            $crtParsed['name']
        );
        $this->assertTrue($this->jmcrt->hasExtensions()) ;
        $this->assertTrue($this->jmcrt->hasQCStatements()) ;
        $this->assertEquals(
            [
              '6a6f51e5cc275d6509eea81b129403f040a008f2',
              ''
            ],
            [
              bin2hex($this->jmcrt->getAuthorityKeyIdentifier()),
              bin2hex($this->jmcrt->getSubjectKeyIdentifier())
            ]
        );
        $this->assertEquals(
            [
              'http://crl.eid.belgium.be/eidc201508.crl'
            ],
            $this->jmcrt->getCDPs()
        );
        $this->assertEquals(
            [
              true,
              true
            ],
            [
              $this->jmcrt->isStartedAt($this->testTime),
              $this->jmcrt->isNotFinishedAt($this->testTime)
            ]
        );
        $this->assertTrue($this->jmcrt->isCurrentAt($this->testTime));
        $this->assertFalse($this->jmcrt->isCA());
        $this->assertEquals(
            [
              'C' => 'BE',
              'CN' => 'Jean-Marc Verbergt (Signature)',
              'SN' => 'Verbergt',
              'GN' => 'Jean-Marc',
              'serialNumber' => '67022330340'
            ],
            $this->jmcrt->getSubjectParsed()
        );
        $this->assertEquals(
            [
              'C' => 'BE',
              'CN' => 'Citizen CA',
              'serialNumber' => '201508'
            ],
            $this->jmcrt->getIssuerParsed()
        );
        $cacrt1 = new X509Certificate(file_get_contents(__DIR__.'/certs/'.TSPServicesTest::testTSPServiceCertFile));
        $this->assertTrue($cacrt1->isCA());
        $this->assertEquals(
            0,
            $cacrt1->getPathLength()
        );
    }

    public function testX509Atrributes()
    {
        $this->getTestCerts();
        $this->assertEquals(
            $this->eucrtAttributes,
            $this->eucrt->getAttributes()
        );
    }

    public function testDistinguishedNames()
    {
        $this->getTestCerts();
        $this->assertEquals(
            $this->eucrtSubject,
            $this->eucrt->getSubjectExpanded()
        );
        $this->assertEquals(
            $this->eucrtIssuerSubject,
            $this->eucrt->getIssuerExpanded()
        );
    }

    public function testIssuerValidate()
    {
        $this->getTestCerts();
        $this->assertEquals(
            0,
            sizeof($this->eucrt->getIssuers())
        );
        $issuer = $this->eucrt->withIssuer($this->euissuercrt);
        $this->assertTrue(
            is_array($this->eucrt->getIssuers())
        );
        $this->assertEquals(
            1,
            sizeof($this->eucrt->getIssuers())
        );
        $issuer = $this->eucrt->withIssuer($this->euissuercrt);
        $this->assertEquals(
            1,
            sizeof($this->eucrt->getIssuers())
        );
        $this->assertEquals(
            'eIDASCertificate\Certificate\X509Certificate',
            get_class($issuer)
        );
        $this->getTestCerts();

        $euissuercrt = new X509Certificate($this->euissuercrt);
        $issuer = $this->eucrt->withIssuer($euissuercrt);

        $this->assertEquals(
            1,
            sizeof($this->eucrt->getIssuers())
        );
    }

    public function testQCIssuer()
    {
        $this->getTestCerts();
        $dataDir = __DIR__.'/../data/';
        $signingCertPEM = file_get_contents($dataDir.'/journal/c-276-1/'.self::lotlSignerHash.'.crt');
        $signingCert = new X509Certificate($signingCertPEM);
        $lotl = new TrustedList(file_get_contents($dataDir.'/eu-lotl.xml'));
        $beTLTitle = 'BE: FPS Economy, SMEs, Self-employed and Energy - Quality and Safety';
        $issuerTSPServiceName = 'QuoVadis BE PKI Certification Authority G2';
        // $eucrt = new X509Certificate($this->eucrt);
        $euissuercrt = new X509Certificate($this->euissuercrt);
        // $euissuercrt->setTSPService($tspServiceAttributes);)
        $lotl->verifyTSL($signingCert);
        $beTLXML = file_get_contents($dataDir.'tl-61c0487109be27255c19cff26d8f56bea621e7f381a7b4cbe7fb4750bd477bf9.xml');
        $beTLPointer = $lotl->getTLPointerPaths()[$beTLTitle];
        $lotl->addTrustedListXML($beTLTitle, $beTLXML);
        $issuerTSPService = ($lotl->getTSPServices(true)[$issuerTSPServiceName]);
        $euissuercrt->setTSPService($issuerTSPService);
        $eucrt = $this->eucrt;
        $eucrt->withIssuer($euissuercrt);
        $eucrtRefAttributes = $this->eucrtAttributes;
        $eucrtRefAttributes['issuerCerts'][$this->euIssuerCrtId] = $this->euIssuercrtAttributes;
        $eucrtAttributes = $eucrt->getAttributes();
        unset($eucrtAttributes['issuerCerts'][self::euIssuercertId]['tspService']['trustServiceProvider']['trustedList']['tslSignatureVerifiedAt']);
        unset($eucrtAttributes['issuerCerts'][self::euIssuercertId]['tspService']['trustServiceProvider']['trustedList']['parentTSL']['tslSignatureVerifiedAt']);
        $this->assertArrayHasKey(
            'issuerCerts',
            $eucrtAttributes
        );
        $this->assertArrayHasKey(
            self::euIssuercertId,
            $eucrtAttributes['issuerCerts']
        );
        $this->assertArrayHasKey(
            'tspService',
            $eucrtAttributes['issuerCerts'][self::euIssuercertId]
        );
        $this->assertEquals(
            TSPServicesTest::getTSPServiceAttributes(),
            $eucrtAttributes['issuerCerts'][self::euIssuercertId]['tspService']
        );
    }
}
