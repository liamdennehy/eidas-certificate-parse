<?php

namespace eIDASCertificate\tests;

use PHPUnit\Framework\TestCase;
use eIDASCertificate\Certificate\X509Certificate;
use eIDASCertificate\TrustedList;
use ASN1\Type\UnspecifiedType;
use eIDASCertificate\tests\Helper;

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
        Helper::getHTTP(TLTest::testTLURI, 'tl');
        $this->testTime = new \DateTime('@1569225604');
        $this->eucrtSubject = [
          [
            'oid' => '2.5.4.6',
            'name' => 'countryName',
            'shortName' => 'C',
            'value' => 'BE'
          ],
          [
            'oid' => '2.5.4.11',
            'name' => 'organizationalUnitName',
            'shortName' => 'OU',
            'value' => 'DG CONNECT'
          ],
          [
            'oid' => '2.5.4.97',
            'name' => 'organizationIdentifier',
            'shortName' => '2.5.4.97',
            'value' => 'VATBE-0949.383.342'
          ],
          [
            'oid' => '2.5.4.10',
            'name' => 'organizationName',
            'shortName' => 'O',
            'value' => 'European Commission'
          ],
          [
            'oid' => '2.5.4.3',
            'name' => 'commonName',
            'shortName' => 'CN',
            'value' => 'EC_CNECT'
          ]
        ];
        $this->eucrtIssuerSubject = [
          [
            'oid' => '2.5.4.6',
            'name' => 'countryName',
            'shortName' => 'C',
            'value' => 'BE'
          ],
          [
            'oid' => '2.5.4.97',
            'name' => 'organizationIdentifier',
            'shortName' => '2.5.4.97',
            'value' => 'NTRBE-0537698318'
          ],
          [
            'oid' => '2.5.4.10',
            'name' => 'organizationName',
            'shortName' => 'O',
            'value' => 'QuoVadis Trustlink BVBA'
          ],
          [
            'oid' => '2.5.4.3',
            'name' => 'commonName',
            'shortName' => 'CN',
            'value' => 'QuoVadis Belgium Issuing CA G2'
          ],
        ];
        $this->eucrtAttributes =
        [
          'subject' => [
            'DN' => '/C=BE/OU=DG CONNECT/2.5.4.97=VATBE-0949.383.342/O=European Commission/CN=EC_CNECT',
            'expandedDN' => $this->eucrtSubject,
            'syntax' => 'The values in the Subject DN are interpreted according to the rules of a Legal Person',
          ],
          'issuer' => [
            'DN' => '/C=BE/2.5.4.97=NTRBE-0537698318/O=QuoVadis Trustlink BVBA/CN=QuoVadis Belgium Issuing CA G2',
            'expandedDN' => $this->eucrtIssuerSubject,
            'uris' => [
              'http://trust.quovadisglobal.com/qvbecag2.crt'
            ],
          ],
          'fingerprint' => 'ccd879b36bb553685becbd12901c7f41f7bd3e07f898fcbbe1eec456b03d7589',
          'notBefore' => 1520438443,
          'notAfter' => 1615133400,
          'skiHex' => 'e811fc46be23b48f3ef7b1d778df0997b8ec4524',
          'skiBase64' => '6BH8Rr4jtI8+97HXeN8Jl7jsRSQ=',
          'akiHex' => '87c9bc3197127a73bb7ec03d4551b401259551ab',
          'akiBase64' => 'h8m8MZcSenO7fsA9RVG0ASWVUas=',
          'statusCheckURIs' => [
            'crl' => [
              'http://crl.quovadisglobal.com/qvbecag2.crl'
            ],
            'ocsp' => [
              'http://uw.ocsp.quovadisglobal.com'
            ]
          ],
          'keySecurity' => [
            'SSCD' =>
              'The private key related to the certified public key resides in '.
              'a Qualified Signature/Seal Creation Device (QSCD) according to '.
              'the Regulation (EU) No 910/2014'
          ],
          'PKIDisclosureStatements' => [
            [
              'url' => 'https://www.quovadisglobal.com/repository',
              'language' => 'en'
            ]
          ],
          'qualification' => [
            'type' => 'eseal',
            'qualified' => 'The certificate is an EU qualified certificate that is issued according to Annex I, III or IV of the Regulation (EU) No 910/2014.',
            'purpose' =>
              'Certificate for Electronic Signatures (QSealC) according to '.
              'Regulation (EU) No 910/2014 Article 38'
          ],
          'keyPurposes' => [
            'keyUsage' => [
              'digitalSignature' => true,
              'nonRepudiation' => true,
              'keyEncipherment' => false,
              'dataEncipherment' => false,
              'keyAgreement' => false,
              'keyCertSign' => false,
              'cRLSign' => false,
              'encipherOnly' => false,
              'decipherOnly' => false,
            ],
            'extendedKeyUsage' => [
              [
                'name' => 'clientAuth',
                'oid' => '1.3.6.1.5.5.7.3.2',
                'url' => 'https://tools.ietf.org/html/rfc5280#section-4.2.1.12'
              ],
              [
                'name' => 'emailProtection',
                'oid' => '1.3.6.1.5.5.7.3.4',
                'url' => 'https://tools.ietf.org/html/rfc5280#section-4.2.1.12'
              ],
              [
                'name' => 'MS_DOCUMENT_SIGNING',
                'oid' => '1.3.6.1.4.1.311.10.3.12',
                'url' => 'https://support.microsoft.com/en-us/help/287547/object-ids-associated-with-microsoft-cryptography'
              ],
            ]
          ],
          'unRecognizedExtensions' => [
            'oid' => '1.2.840.113583.1.1.9.2',
            'value' => 'MAMCAQE='
          ],
          'unRecognizedExtensions' => [
            'oid' => '1.2.840.113583.1.1.9.1',
            'value' => 'MCQCAQGGH2h0dHA6Ly90cy5xdW92YWRpc2dsb2JhbC5jb20vYmU='
          ],
          'unRecognizedExtensions' => [
            [
              'oid' => '2.5.29.32',
              'value' =>
                'MFEwRAYKKwYBBAG+WAGDEDA2MDQGCCsGAQUFBwIBFihodHRwOi8vd3d3LnF1b3'.
                'ZhZGlzZ2xvYmFsLmNvbS9yZXBvc2l0b3J5MAkGBwQAi+xAAQM='
            ],
            [
              'oid' => '1.2.840.113583.1.1.9.2',
              'value' => 'MAMCAQE='
            ],
            [
              'oid' => '1.2.840.113583.1.1.9.1',
              'value' =>
                'MCQCAQGGH2h0dHA6Ly90cy5xdW92YWRpc2dsb2JhbC5jb20vYmU='
            ],
          ],
          'findings' => [
            'warning' => [
              'extensions' => [
                [
                  'Unhandled extension \'1.2.840.113583.1.1.9.1\': MCQCAQGGH'.
                  '2h0dHA6Ly90cy5xdW92YWRpc2dsb2JhbC5jb20vYmU='
                ],
                [
                  'Unhandled extension \'1.2.840.113583.1.1.9.2\': MAMCAQE='
                ],
                [
                  'Unhandled extension \'certificatePolicies\' (2.5.29.32): MFEwRAYKKwYBBAG+WAGDED'.
                  'A2MDQGCCsGAQUFBwIBFihodHRwOi8vd3d3LnF1b3ZhZGlzZ2xvYmFsLmN'.
                  'vbS9yZXBvc2l0b3J5MAkGBwQAi+xAAQM='
                ]
              ]
            ]
          ]
        ];
        $this->euIssuercrtIssuerAttributes = [
          [
            'oid' => '2.5.4.6',
            'name' => 'countryName',
            'shortName' => 'C',
            'value' => 'BM'
          ],
          [
            'oid' => '2.5.4.10',
            'name' => 'organizationName',
            'shortName' => 'O',
            'value' => 'QuoVadis Limited'
          ],
          [
            'oid' => '2.5.4.3',
            'name' => 'commonName',
            'shortName' => 'CN',
            'value' => 'QuoVadis Enterprise Trust CA 1 G3'
          ]
        ];

        $this->eucrtIssuerTSPService =
          TSPServicesTest::getTSPServiceAttributes();

        $this->euIssuercrtAttributes =
        [
          'subject' => [
            'DN' => '/C=BE/2.5.4.97=NTRBE-0537698318/O=QuoVadis Trustlink BVBA/CN=QuoVadis Belgium Issuing CA G2',
            'expandedDN' => $this->eucrtIssuerSubject,
          ],
          'issuer' => [
            'DN' => '/C=BM/O=QuoVadis Limited/CN=QuoVadis Enterprise Trust CA 1 G3',
            'expandedDN' => $this->euIssuercrtIssuerAttributes,
            'uris' => [
              'http://trust.quovadisglobal.com/qventca1g3.crt'
            ],
          ],
          'notBefore' => 1465820525,
          'notAfter' => 1781353325,
          'fingerprint' => 'd90b40132306d1094608b1b9a2f6a9e23b45fe121fef514a1c9df70a815ad95c',
          'skiHex' => '87c9bc3197127a73bb7ec03d4551b401259551ab',
          'skiBase64' => 'h8m8MZcSenO7fsA9RVG0ASWVUas=',
          'akiHex' => '6c26bd605529294e663207a0ff638b835a4b34c6',
          'akiBase64' => 'bCa9YFUpKU5mMgeg/2OLg1pLNMY=',
          'isCA' => true,
          'tspService' => $this->eucrtIssuerTSPService,
          'statusCheckURIs' => [
            'crl' => [
              'http://crl.quovadisglobal.com/qventca1g3.crl'
            ],
            'ocsp' => [
              'http://ocsp.quovadisglobal.com'
            ],
          ],
          'keyPurposes' => [
            'keyUsage' => [
              'digitalSignature' => false,
              'nonRepudiation' => false,
              'keyEncipherment' => false,
              'dataEncipherment' => false,
              'keyAgreement' => false,
              'keyCertSign' => true,
              'cRLSign' => true,
              'encipherOnly' => false,
              'decipherOnly' => false,
            ]
          ],
          'unRecognizedExtensions' => [
            [
              'oid' => '2.5.29.32',
              'value' => 'MAgwBgYEVR0gAA=='
            ]
          ],
          'findings' => [
            'warning' => [
              'extensions' => [
                [
                  'Unhandled extension \'certificatePolicies\' (2.5.29.32): MAgwBgYEVR0gAA=='
                ]
              ]
            ]
          ],
        ];
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
        $this->assertEquals(
            '/C=BE/OU=DG CONNECT/2.5.4.97=VATBE-0949.383.342'.
            '/O=European Commission/CN=EC_CNECT',
            $this->eucrt->getSubjectDN()
        );
        $this->assertEquals(
            '/C=BE/2.5.4.97=NTRBE-0537698318/O=QuoVadis Trustlink BVBA'.
            '/CN=QuoVadis Belgium Issuing CA G2',
            $this->eucrt->getIssuerDN()
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
              hash(
                  'sha1',
                  UnspecifiedType::fromDER(
                      $this->eucrt->getPublicKey()
                  )->asSequence()
                ->at(1)->asBitString()->string()
              )
            ]
        );
        $this->assertTrue($this->eucrt->hasExtensions());
        $this->assertEquals(
            [
              'authorityInfoAccess',
              'subjectKeyIdentifier',
              'authorityKeyIdentifier',
              'unknown-2.5.29.32',
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
        // $crtParsed = $this->mocrt->getParsed();
        $this->assertEquals(
            '/C=BE/L=BE/O=European Commission/OU=0949.383.342'.
            '/CN=Maarten Joris Ottoy/SN=Ottoy/givenName=Maarten Joris'.
            '/serialNumber=10304444110080837592'.
            '/emailAddress=maarten.ottoy@ec.europa.eu'.
            '/title=Professional Person',
            $this->mocrt->getSubjectDN()
        );
        // $this->assertEquals(
        //     [
        //       ['C' => 'BE'],
        //       'L' => 'BE',
        //       'O' => 'European Commission',
        //       'OU' => '0949.383.342',
        //       'CN' => 'Maarten Joris Ottoy',
        //       'SN' => 'Ottoy',
        //       'GN' => 'Maarten Joris',
        //       'serialNumber' => '10304444110080837592',
        //       'emailAddress' => 'maarten.ottoy@ec.europa.eu',
        //       'title' => 'Professional Person'
        //     ],
        //     $this->mocrt->getSubjectExpanded()
        // );
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
        // $crtParsed = $this->jmcrt->getParsed();
        $this->assertEquals(
            '/C=BE/CN=Jean-Marc Verbergt (Signature)/SN=Verbergt/givenName=Jean-Marc/serialNumber=67022330340',
            $this->jmcrt->getSubjectDN()
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
            '/C=BE/CN=Jean-Marc Verbergt (Signature)/SN=Verbergt/givenName=Jean-Marc/serialNumber=67022330340',
            $this->jmcrt->getSubjectDN()
        );
        $this->assertEquals(
            '/C=BE/CN=Citizen CA/serialNumber=201508',
            $this->jmcrt->getIssuerDN()
        );
        $cacrt1 = new X509Certificate(
            file_get_contents(
                __DIR__.'/certs/'.TSPServicesTest::testTSPServiceCertFile
            )
        );
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
        // $eucrt = new X509Certificate($this->eucrt);
        $euissuercrt = new X509Certificate($this->euissuercrt);
        // $euissuercrt->setTSPService($tspServiceAttributes);)
        $lotl->verifyTSL($signingCert);
        $testTLXML = file_get_contents($dataDir.TLTest::testTLXMLFileName);
        $lotl->addTrustedListXML(TLTest::testTLName, $testTLXML);
        $issuerTSPService = ($lotl->getTSPServices(true)[TSPServicesTest::testTSPServiceName]);
        $euissuercrt->setTSPService($issuerTSPService);
        $eucrt = $this->eucrt;
        $eucrt->withIssuer($euissuercrt);
        $eucrtRefAttributes = $this->eucrtAttributes;
        $eucrtRefAttributes['issuerCerts'][0] = $this->euIssuercrtAttributes;
        $eucrtAttributes = $eucrt->getAttributes();
        // $this->assertEquals(
        //   [],
        //   array_keys($eucrtAttributes['issuer']['certificates'][0])
        // );
        unset($eucrtAttributes['issuer']['certificates'][0]['tspService']['trustServiceProvider']['trustedList']['tslSignatureVerifiedAt']);
        unset($eucrtAttributes['issuer']['certificates'][0]['tspService']['trustServiceProvider']['trustedList']['parentTSL']['tslSignatureVerifiedAt']);
        $this->assertArrayHasKey(
            'certificates',
            $eucrtAttributes['issuer']
        );
        $this->assertEquals(
            1,
            sizeof($eucrtAttributes['issuer']['certificates'])
        );
        $this->assertEquals(
            $this->euIssuercrtAttributes,
            $eucrtAttributes['issuer']['certificates'][0]
        );
        $this->assertArrayHasKey(
            'tspService',
            $eucrtAttributes['issuer']['certificates'][0]
        );
        $this->assertEquals(
            TSPServicesTest::getTSPServiceAttributes(),
            $eucrtAttributes['issuer']['certificates'][0]['tspService']
        );
    }
}
