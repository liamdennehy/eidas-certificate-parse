<?php

namespace eIDASCertificate\tests;

use PHPUnit\Framework\TestCase;
use eIDASCertificate\Certificate\DistinguishedName;
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
    const eucrtPublicKeyPEM =
        "-----BEGIN PUBLIC KEY-----\n".
        "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA6OaxkP4aEj/JK+Aw13o5\n".
        "OrMh45ZDMLMMNbUtLnPHvSFH4s4tqojFA+m/xyGJk4mAwQemabOOy+wNzjYG+xfo\n".
        "KjPgYbjDzRG10wle9pSpjqm++jzNcCSqwcH9CBBJbe51NQiAtPLnylHA7xoVjvu6\n".
        "8axzfGkhk9BfRgx5uK7Ip6mVeWbHBM7Acps7e/Rs2KwinuhTibGDFBZ3G6rg63q1\n".
        "hinnBvqa5z6xXIsf/lcZrJd14vO4JawfKHrQqHItW1l+0RMUXCllVhKSWIwdzYOU\n".
        "xv9jkS4hxC0evNLcPjGfJP4sHTG8ZotppNrILEv3VuMv93gfkb1RwKGyqil19m7i\n".
        "ewIDAQAB\n".
        "-----END PUBLIC KEY-----";
    const eucrtPublicKey =
        'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA6OaxkP4aEj'.
        '/JK+Aw13o5OrMh45ZDMLMMNbUtLnPHvSFH4s4tqojFA+m/xyGJk4mAwQemabOOy'.
        '+wNzjYG+xfoKjPgYbjDzRG10wle9pSpjqm++jzNcCSqwcH9CBBJbe51NQiAtPLn'.
        'ylHA7xoVjvu68axzfGkhk9BfRgx5uK7Ip6mVeWbHBM7Acps7e/Rs2KwinuhTibG'.
        'DFBZ3G6rg63q1hinnBvqa5z6xXIsf/lcZrJd14vO4JawfKHrQqHItW1l+0RMUXC'.
        'llVhKSWIwdzYOUxv9jkS4hxC0evNLcPjGfJP4sHTG8ZotppNrILEv3VuMv93gfk'.
        'b1RwKGyqil19m7iewIDAQAB';
    const euIssuercertPublicKey =
        'MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAmLsm3G2sWV/LTr0gC5iOXSSL'.
        'DXGEdSFvK7dsEU4wgvy3kv2sL1bpx4g9UjmoQuUiLVfvuIWOSmcunFA9CoTf+vK4uTxq'.
        'vYjOVdd6dAjUx4D+xgGGdQdONKFNv+V6PPZ7KziNO/QfJWZhw31sRv/3vybbZdVFcaEo'.
        'GhisYw6GpJ+nQfzyTuvwnjyFdNsS5qA4YgNXrmHcH91PMrM3pesCa0iAhB24snUAJjyg'.
        'gJWXLR3rUm7QXgOulkfQtFEPwvq66kmVt6To45h8CvmCcwqDLPp/H1N2oMuTfEnxqDFw'.
        'UP4pRHcCzUt9CWNdk8wUyyUWnWd5/YMFI2rMK5tdycfuwzxvLJn4LOUEqn0hvxtV4w1Q'.
        '15MV7ipM1AiPpaWXE1WU7BNFcKO2aPWygQnkJOEKW7fgAq0QG0FdqqGb12v1c06EQvRi'.
        '5D5SJQNq15A5cpqy8XdaeXkANP/IlAMI1cnsPMBSIySuQ00zQVqHiIv+q3kls3oz7PV1'.
        'aglrZ3pJXp9BZGPdcZjhJh5JkVaF8zQ6qrLPa+YO8/ud2Bklt6I0E4EY/637VhcPYTlf'.
        'xmvZIPfHjM8HWdjBg2c/i+sd5CsIfeeUOWlUZV3jZbtgQijhe3meejHpbYzggZKM0jUU'.
        '8/p6vsvzBKRhqj2bgABByUcFaLHHLTBX3BKrSpS+hjgan7kCAwEAAQ==';

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
            'ski' => '6BH8Rr4jtI8+97HXeN8Jl7jsRSQ=',
          ],
          'issuer' => [
            'DN' => '/C=BE/2.5.4.97=NTRBE-0537698318/O=QuoVadis Trustlink BVBA/CN=QuoVadis Belgium Issuing CA G2',
            'expandedDN' => $this->eucrtIssuerSubject,
            'uris' => [
              'http://trust.quovadisglobal.com/qvbecag2.crt'
            ],
            'aki' => 'h8m8MZcSenO7fsA9RVG0ASWVUas=',
            'serialNumber' => '510758012567249096883552881202149149901456017681',
            'isSelf' => false
          ],
          'fingerprint' => 'ccd879b36bb553685becbd12901c7f41f7bd3e07f898fcbbe1eec456b03d7589',
          'notBefore' => 1520438443,
          'notAfter' => 1615133400,
          'statusCheckURIs' => [
            'crl' => [
              'http://crl.quovadisglobal.com/qvbecag2.crl'
            ],
            'ocsp' => [
              'http://uw.ocsp.quovadisglobal.com'
            ]
          ],
          'privateKey' => [
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
            'type' => 'QSealC',
            'qualified' => 'The certificate is an EU qualified certificate that is issued according to Annex I, III or IV of the Regulation (EU) No 910/2014.',
            'purpose' =>
              'Certificate for Electronic Seals (QSealC) according to '.
              'Regulation (EU) No 910/2014 Article 38'
          ],
          'publicKey' => [
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
            ],
            'qualified' => 'eseal',
            'key' => self::eucrtPublicKey
          ],
          'unRecognizedExtensions' => [
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
                'Unhandled extension \'1.2.840.113583.1.1.9.1\': MCQCAQGGH'.
                  '2h0dHA6Ly90cy5xdW92YWRpc2dsb2JhbC5jb20vYmU=',
                'Unhandled extension \'1.2.840.113583.1.1.9.2\': MAMCAQE='
              ],
              'certificatePolicies' => [
                'Unrecognised certificatePolicy OID 1.3.6.1.4.1.8024.1.400 (unknown): MEQGCisGAQQBvlgBgxAwNjA0BggrBgEFBQcCARYoaHR0cDovL3d3dy5xdW92YWRpc2dsb2JhbC5jb20vcmVwb3NpdG9yeQ==',
                'Unrecognised certificatePolicy OID 0.4.0.194112.1.3 (unknown): MAkGBwQAi+xAAQM='
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
          TSPServicesTest::getEUTSPServiceAttributes();

        $this->euIssuercrtAttributes =
        [
          'subject' => [
            'DN' => '/C=BE/2.5.4.97=NTRBE-0537698318/O=QuoVadis Trustlink BVBA/CN=QuoVadis Belgium Issuing CA G2',
            'expandedDN' => $this->eucrtIssuerSubject,
            'ski' => 'h8m8MZcSenO7fsA9RVG0ASWVUas=',
          ],
          'issuer' => [
            'DN' => '/C=BM/O=QuoVadis Limited/CN=QuoVadis Enterprise Trust CA 1 G3',
            'expandedDN' => $this->euIssuercrtIssuerAttributes,
            'uris' => [
              'http://trust.quovadisglobal.com/qventca1g3.crt'
            ],
            'aki' => 'bCa9YFUpKU5mMgeg/2OLg1pLNMY=',
            'serialNumber' => '370861943658773060475449278572584178262799314517',
            'isSelf' => false
          ],
          'notBefore' => 1465820525,
          'notAfter' => 1781353325,
          'fingerprint' => 'd90b40132306d1094608b1b9a2f6a9e23b45fe121fef514a1c9df70a815ad95c',
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
          'publicKey' => [
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
            ],
            'key' => self::euIssuercertPublicKey
          ],
          'findings' => [
            'warning' => [
              'certificatePolicies' => [
                'Unrecognised certificatePolicy OID 2.5.29.32.0 (unknown): MAYGBFUdIAA='
              ]
            ]
          ],
        ];
        $this->v1crtSubject = [
          [
            'oid' => '2.5.4.6',
            'name' => 'countryName',
            'shortName' => 'C',
            'value' => 'US'
          ],
          [
            'oid' => '2.5.4.10',
            'name' => 'organizationName',
            'shortName' => 'O',
            'value' => 'VeriSign, Inc.'
          ],
          [
            'oid' => '2.5.4.11',
            'name' => 'organizationalUnitName',
            'shortName' => 'OU',
            'value' => 'VeriSign Trust Network'
          ],
          [
            'oid' => '2.5.4.11',
            'name' => 'organizationalUnitName',
            'shortName' => 'OU',
            'value' => '(c) 1999 VeriSign, Inc. - For authorized use only'
          ],
          [
            'name' => 'commonName',
            'shortName' => 'CN',
            'oid' => '2.5.4.3',
            'value' => 'VeriSign Class 3 Public Primary Certification Authority - G3'
          ]
        ];
        $this->v1CertPublickey =
          'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAy7qcUvx4Hxoebxs3c734yWu'.
          'UEjBP8DZH9dCRCvUXyKVhwRZATfuKYZDldiDBEQZ9qyxupvURQY76La0qYVmkZyZM0O'.
          'i8UltwIARY0XrJpGm8gxdkrQWLvNBYzo2M9evwQkkLnZcnZzJu4a6TFRxwvCBNLxjek'.
          'ojobIVXERrpfuMmEVSiRZZVg8owiejc2KPtKoA/f3llVz4VIGYIL5WTv6pHL6hGl/AS'.
          '4v7CCitR5nbmt0a34g2mzKjDTFlVieboU1wc6p3wYhYLp8lfDPDewnbOr/dq8vpBpqI'.
          'zFMnlemPTnmI31YVlng7mUyR0G14dElNbxyzng0k7Fa6KaLlXlwIDAQAB';
        $this->v1crtAttributes =
        [
          'subject' => [
            'DN' => '/C=US/O=VeriSign, Inc.'.
              '/OU=VeriSign Trust Network'.
              '/OU=(c) 1999 VeriSign, Inc. - For authorized use only'.
              '/CN=VeriSign Class 3 Public Primary Certification Authority - G3',
            'expandedDN' => $this->v1crtSubject,
          ],
          'issuer' => [
            'DN' => '/C=US/O=VeriSign, Inc.'.
              '/OU=VeriSign Trust Network'.
              '/OU=(c) 1999 VeriSign, Inc. - For authorized use only'.
              '/CN=VeriSign Class 3 Public Primary Certification Authority - G3',
            'expandedDN' => $this->v1crtSubject,
            'isSelf' => true,
            'serialNumber' => '206684696279472310254277870180966723415'
          ],
          'fingerprint' => 'eb04cf5eb1f39afa762f2bb120f296cba520c1b97db1589565b81cb9a17b7244',
          'notBefore' => 938736000,
          'notAfter' => 2099865599,
          'publicKey' => [
            'key' => $this->v1CertPublickey
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

    public function testV1Parse()
    {
        $crtFile = file_get_contents(__DIR__.'/certs/v1.crt');
        $v1Cert = new X509Certificate($crtFile);

        $this->assertEquals(
            '/C=US/O=VeriSign, Inc.'.
            '/OU=VeriSign Trust Network'.
            '/OU=(c) 1999 VeriSign, Inc. - For authorized use only'.
            '/CN=VeriSign Class 3 Public Primary Certification Authority - G3',
            $v1Cert->getSubjectDN()
        );
        $this->assertEquals(
            '/C=US/O=VeriSign, Inc.'.
            '/OU=VeriSign Trust Network'.
            '/OU=(c) 1999 VeriSign, Inc. - For authorized use only'.
            '/CN=VeriSign Class 3 Public Primary Certification Authority - G3',
            $v1Cert->getIssuerDN()
        );
        $this->assertFalse($v1Cert->hasExtensions());
        $this->assertEquals(
            $this->v1crtAttributes,
            $v1Cert->getAttributes()
        );
        $this->assertTrue(
            $v1Cert->isCurrentAt($this->testTime)
        );
        $this->assertFalse(
            $v1Cert->isCurrentAt(new \DateTime('1998-12-12 12:00 UTC'))
        );
        $this->assertFalse(
            $v1Cert->isCurrentAt(new \DateTime('2036-08-01 12:00 UTC'))
        );
        $this->assertEquals(
            'sha1WithRSAEncryption',
            $v1Cert->getSignatureAlgorithmName()
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
              'e811fc46be23b48f3ef7b1d778df0997b8ec4524'
            ],
            [
              bin2hex($this->eucrt->getAuthorityKeyIdentifier()),
              bin2hex($this->eucrt->getSubjectKeyIdentifier())
            ]
        );
        $this->assertTrue($this->eucrt->hasExtensions());
        $this->assertEquals(
            [
              'authorityInfoAccess',
              'subjectKeyIdentifier',
              'authorityKeyIdentifier',
              'certificatePolicies',
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
            '/CN=Maarten Joris Ottoy/SN=Ottoy/GN=Maarten Joris'.
            '/serialNumber=10304444110080837592'.
            '/emailAddress=maarten.ottoy@ec.europa.eu'.
            '/title=Professional Person',
            $this->mocrt->getSubjectDN()
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
        $this->assertEquals(
            self::eucrtPublicKeyPEM,
            $this->eucrt->getPublicKeyPEM()
        );
        // $crtParsed = $this->jmcrt->getParsed();
        $this->assertEquals(
            '/C=BE/CN=Jean-Marc Verbergt (Signature)/SN=Verbergt/GN=Jean-Marc/serialNumber=67022330340',
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
            '/C=BE/CN=Jean-Marc Verbergt (Signature)/SN=Verbergt/GN=Jean-Marc/serialNumber=67022330340',
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
        $this->assertEquals(
            'sha1WithRSAEncryption',
            $this->jmcrt->getSignatureAlgorithmName()
        );
        $this->assertEquals(
            [],
            $this->jmcrt->getSignatureAlgorithmParameters()
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
        $issuerTSPService = ($lotl->getTSPServices(true)[TSPServicesTest::EUTSPServiceName]);
        $euissuercrt->setTSPService($issuerTSPService);
        $eucrt = $this->eucrt;
        $eucrt->withIssuer($euissuercrt);
        $eucrtRefAttributes = $this->eucrtAttributes;
        $eucrtRefAttributes['issuerCerts'][0] = $this->euIssuercrtAttributes;
        $eucrtAttributes = $eucrt->getAttributes();
        unset($eucrtAttributes['issuer']['certificates'][0]['tspService']['trustServiceProvider']['trustedList']['signature']['verifiedAt']);
        unset($eucrtAttributes['issuer']['certificates'][0]['tspService']['trustServiceProvider']['trustedList']['parentTSL']['signature']['verifiedAt']);
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
            TSPServicesTest::getEUTSPServiceAttributes(),
            $eucrtAttributes['issuer']['certificates'][0]['tspService']
        );
    }

    public function testParseDN()
    {
        $dnDER = base64_decode(
            'MIIBHzELMAkGA1UEBhMCUEwxFDASBgNVBAgMC21hem93aWVja2llMREwDwYDVQQHDA'.
            'hXYXJzemF3YTEjMCEGA1UECwwaQml1cm8gT3R3YXJ0ZWogQmFua293b8WbY2kxPTA7'.
            'BgNVBBAwNAwMUHXFgmF3c2thIDE1DA8wMC05NzUgV2Fyc3phd2EMC21hem93aWVja2'.
            'llDAZQb2xza2ExHjAcBgNVBGEMFVBTRFBMLVBGU0EtNTI1MDAwNzczODFEMEIGA1UE'.
            'Cgw7UG93c3plY2huYSBLYXNhIE9zemN6xJlkbm/Fm2NpIEJhbmsgUG9sc2tpIFNww7'.
            'PFgmthIEFrY3lqbmExHTAbBgNVBAMMFHNhbmRib3guYXBpLnBrb2JwLnBs'
        );
        $dn = new DistinguishedName(UnspecifiedType::fromDER($dnDER));
        $this->assertEquals(
            '/C=PL/ST=mazowieckie/L=Warszawa/OU=Biuro Otwartej '.
            'Bankowości/postalAddress=Puławska 15/postalAddress=00-975 '.
            'Warszawa/postalAddress=mazowieckie/postalAddress=Polska'.
            '/2.5.4.97=PSDPL-PFSA-5250007738/O=Powszechna Kasa Oszczędności '.
            'Bank Polski Spółka Akcyjna/CN=sandbox.api.pkobp.pl',
            $dn->getDN()
        );
    }
}
