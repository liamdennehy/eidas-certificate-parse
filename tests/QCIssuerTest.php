<?php

namespace eIDASCertificate\tests;

use PHPUnit\Framework\TestCase;
use PHPUnit\Framework\Attributes\Before;
use eIDASCertificate\DistinguishedName;
use eIDASCertificate\Certificate\X509Certificate;
use eIDASCertificate\TrustedList;
use ASN1\Type\UnspecifiedType;
use eIDASCertificate\tests\Helper;

class QCIssuerTest extends TestCase
{
    private $testTime;
    private $eucrtSubject;
    private $eucrtIssuerSubject;
    private $eucrtAttributes;
    private $euIssuercrtIssuerAttributes;
    private $eucrtIssuerTSPService;
    private $euIssuercrtAttributes;
    private $v1crtSubject;
    private $v1CertPublickey;
    private $v1crtAttributes;
    private $mocrtPEM;
    private $mocrt;
    private $jmcrtPEM;
    private $jmcrt;
    private $eucrtPEM;
    private $eucrt;
    private $euissuercrtPEM;
    private $euissuercrt;
    const jmcrtfile = 'Jean-Marc Verbergt (Signature).crt';
    const mocrtfile = 'Maarten Joris Ottoy.crt';
    const eucrtfile = 'EUROPEAN COMMISSION.crt';
    const euissuercrtfile = 'DIGITALSIGN QUALIFIED CA G1.pem';
    const euIssuercertId = 'd90b40132306d1094608b1b9a2f6a9e23b45fe121fef514a1c9df70a815ad95c';
    const lotlSignerHash = '8e508f03b132500c3403db66e9dd39cd78f4657c840958a77d34e7bd621468e7';
    const eucrtPublicKeyPEM =
        "-----BEGIN PUBLIC KEY-----\n".
        "MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEApZh4ED2RgBESUaceglE2\n".
        "ltvLjgb5NIlyAcj1C3JeViMHbfiFIBjIm9b6Aq+ijCeySuiB9Q/oY6ZCAQVlfffl\n".
        "jSwHB+mlV6YSh70f0CP9ylPXgip0HTlXhrzwBJF9HRVrXGZAmsOwFlapkfHQQQcF\n".
        "y0gXkGPJMwBxDJuFr7gA4ii2nd0X/tkDcK7gZhs30G5DLKp+quMx24PPMONXAoLX\n".
        "toSwt6/rQLUWcgn8VUR1reUlIaKUPknJRx5NpFyi3WvDqCMqs5WHA/9Qd968nckK\n".
        "xCy4DOR/uK/MfNi4889H1Syx5zCvs73kWvjBs9gjJfYA5OWJ4ALsYxVcc3X/7gsf\n".
        "vid2+glgRJxfCY31KSJvf4bpOq44JDG81fMc9lv3lu0KhKdWmsKfXg7cJdRNkwQq\n".
        "SE+4pbx0jqlHYlIZu1P7EGRxzXBhWVSfMTd35grlJJ69RPYI7Akz4ByNKhRpFMEg\n".
        "2wP97MMO+/u+1sXVdxxomOgI2S6vNrJOwyzMYO8AXXvUtjr2U1jrIrS7OtL7dz+E\n".
        "Qdy1drkogLc+lasEZDmbDvcp6tG+cCHMNl6ZWq4+TUPn1ok18egdebLVtLnasdZg\n".
        "7Acf7aps4N2HwaQfAdcHNKkWK3UqDZuulq+HO01oaWPoawsUBuvyiQJQmWU44tDx\n".
        "N/L1WeflGrT7tVN13x0DGD0CAwEAAQ==\n".
        "-----END PUBLIC KEY-----";
    const eucrtPublicKey =
        'MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEApZh4ED2RgBESUaceglE2ltvLjg'.
        'b5NIlyAcj1C3JeViMHbfiFIBjIm9b6Aq+ijCeySuiB9Q/oY6ZCAQVlfffljSwHB+mlV6YS'.
        'h70f0CP9ylPXgip0HTlXhrzwBJF9HRVrXGZAmsOwFlapkfHQQQcFy0gXkGPJMwBxDJuFr7'.
        'gA4ii2nd0X/tkDcK7gZhs30G5DLKp+quMx24PPMONXAoLXtoSwt6/rQLUWcgn8VUR1reUl'.
        'IaKUPknJRx5NpFyi3WvDqCMqs5WHA/9Qd968nckKxCy4DOR/uK/MfNi4889H1Syx5zCvs7'.
        '3kWvjBs9gjJfYA5OWJ4ALsYxVcc3X/7gsfvid2+glgRJxfCY31KSJvf4bpOq44JDG81fMc'.
        '9lv3lu0KhKdWmsKfXg7cJdRNkwQqSE+4pbx0jqlHYlIZu1P7EGRxzXBhWVSfMTd35grlJJ'.
        '69RPYI7Akz4ByNKhRpFMEg2wP97MMO+/u+1sXVdxxomOgI2S6vNrJOwyzMYO8AXXvUtjr2'.
        'U1jrIrS7OtL7dz+EQdy1drkogLc+lasEZDmbDvcp6tG+cCHMNl6ZWq4+TUPn1ok18egdeb'.
        'LVtLnasdZg7Acf7aps4N2HwaQfAdcHNKkWK3UqDZuulq+HO01oaWPoawsUBuvyiQJQmWU4'.
        '4tDxN/L1WeflGrT7tVN13x0DGD0CAwEAAQ==';
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
    const gsDocSignQRSCAFile = 'GlobalSign Atlas E45 Qualified Remote Signing CA 2020.crt';

    #[Before]
    public function setUpHere()
    {
        // Helper::getHTTP(TLTest::testTLURI, 'tl');
        $this->testTime = (int)(new \DateTime('@1569225604'))->format('U');
        $this->eucrtSubject = [
          [
            'oid' => '2.5.4.6',
            'name' => 'countryName',
            'shortName' => 'C',
            'value' => 'LU'
          ],
          [
            'oid' => '2.5.4.11',
            'name' => 'organizationalUnitName',
            'shortName' => 'OU',
            'value' => 'Certificate Profile - Qualified Certificate - Organization'
          ],
          [
            'oid' => '2.5.4.11',
            'name' => 'organizationalUnitName',
            'shortName' => 'OU',
            'value' => 'Directorate-General for Digital Services (DIGIT)'
          ],
          [
            'oid' => '2.5.4.97',
            'name' => 'organizationIdentifier',
            'shortName' => '2.5.4.97',
            'value' => 'LEIXG-254900ZNYA1FLUQ9U393'
          ],
          [
            'oid' => '2.5.4.10',
            'name' => 'organizationName',
            'shortName' => 'O',
            'value' => 'EUROPEAN COMMISSION'
          ],
          [
            'oid' => '1.2.840.113549.1.9.1',
            'name' => 'emailAddress',
            'shortName' => 'emailAddress',
            'value' => 'digit-dmo@ec.europa.eu'
          ],
          [
            'name' => 'commonName',
            'shortName' => 'CN',
            'oid' => '2.5.4.3',
            'value' => 'EUROPEAN COMMISSION'
            ]
        ];
        $this->eucrtIssuerSubject = [
          [
            'oid' => '2.5.4.6',
            'name' => 'countryName',
            'shortName' => 'C',
            'value' => 'PT'
          ],
          [
            'oid' => '2.5.4.10',
            'name' => 'organizationName',
            'shortName' => 'O',
            'value' => 'DigitalSign Certificadora Digital'
          ],
          [
            'oid' => '2.5.4.3',
            'name' => 'commonName',
            'shortName' => 'CN',
            'value' => 'DIGITALSIGN QUALIFIED CA G1'
          ],
        ];
        $this->eucrtAttributes =
        [
          'x509Version' => 3,
          'subject' => [
            'DN' => '/C=LU/OU=Certificate Profile - Qualified Certificate - Organization/OU=Directorate-General for Digital Services (DIGIT)/2.5.4.97=LEIXG-254900ZNYA1FLUQ9U393/O=EUROPEAN COMMISSION/emailAddress=digit-dmo@ec.europa.eu/CN=EUROPEAN COMMISSION',
            'expandedDN' => $this->eucrtSubject,
            'syntax' => 'The values in the Subject DN are interpreted according to the rules of a Legal Person',
            'ski' => 'lO5hwcl9/63issm59r+TIHeJSZw=',
            'altNames' => [
              'email' => [
                0 => 'digit-dmo@ec.europa.eu'
                ]
              ],
          ],
          'issuer' => [
            'DN' => '/C=PT/O=DigitalSign Certificadora Digital/CN=DIGITALSIGN QUALIFIED CA G1',
            'expandedDN' => $this->eucrtIssuerSubject,
            'uris' => [
              'https://qca-g1.digitalsign.pt/DIGITALSIGNQUALIFIEDCAG1.p7b'
            ],
            'aki' => 'c0nxQBwUBHyaEn/6L81cZyMY6RQ=',
            'serialNumber' => '73c21c494b5510a00c32f1e6f50594d39917b0f5',
            'isSelf' => false
          ],
          'fingerprint' => 'e0a620fbb6747362bb933ac44169d676a553444716cf5f31605f12a22b8396b1',
          'notBefore' => 1700215906,
          'notAfter' => 1826446306,
          'statusCheckURIs' => [
            'crl' => [
              'https://qca-g1.digitalsign.pt/DIGITALSIGNQUALIFIEDCAG1.crl'
            ],
            'ocsp' => [
              'https://qca-g1.digitalsign.pt/ocsp'
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
              'url' => 'https://qca-g1.digitalsign.pt/PDS_en.pdf',
              'language' => 'en'
            ],
            [
              'url' => 'https://qca-g1.digitalsign.pt/PDS_pt.pdf',
              'language' => 'pt'
            ],
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
              'digitalSignature' => false,
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
              // [
              //   'name' => 'MS_DOCUMENT_SIGNING',
              //   'oid' => '1.3.6.1.4.1.311.10.3.12',
              //   'url' => 'https://support.microsoft.com/en-us/help/287547/object-ids-associated-with-microsoft-cryptography'
              // ],
            ],
            'qualified' => 'eseal',
            'key' => self::eucrtPublicKey
          ],
          // 'unRecognizedExtensions' => [
          //   [
          //     'oid' => '1.2.840.113583.1.1.9.2',
          //     'value' => 'MAMCAQE='
          //   ],
          //   [
          //     'oid' => '1.2.840.113583.1.1.9.1',
          //     'value' =>
          //       'MCQCAQGGH2h0dHA6Ly90cy5xdW92YWRpc2dsb2JhbC5jb20vYmU='
          //   ],
          // ],
          'findings' => [
            'warning' => [
              // 'extensions' => [
              //   'Unhandled extension \'1.2.840.113583.1.1.9.1\': MCQCAQGGH'.
              //     '2h0dHA6Ly90cy5xdW92YWRpc2dsb2JhbC5jb20vYmU=',
              //   'Unhandled extension \'1.2.840.113583.1.1.9.2\': MAMCAQE='
              // ],
              // 'certificatePolicies' => [
              //   'Certificate Policy from unknown vendor as oid \'1.3.6.1.4.1.8024.1.400\': '.
              //   'MEQGCisGAQQBvlgBgxAwNjA0BggrBgEFBQcCARYoaHR0cDovL3d3dy5xdW92YWRpc2dsb2JhbC5jb20vcmVwb3NpdG9yeQ==',
              //   'Unrecognised \'ETSI\' Certificate Policy as oid \'0.4.0.194112.1.3\': MAkGBwQAi+xAAQM='
              // ]
              'certificatePolicies' => [
                0 => "Certificate Policy from unknown vendor as oid '1.3.6.1.4.1.25596.4.1.1': MDcGCysGAQQBgcd8BAEBMCgwJgYIKwYBBQUHAgEWGmh0dHBzOi8vcGtpLmRpZ2l0YWxzaWduLnB0",
                1 => "Certificate Policy from unknown vendor as oid '1.3.6.1.4.1.25596.4.2.1.1.1.6': MBAGDisGAQQBgcd8BAIBAQEG",
                2 => "Unrecognised 'ETSI' Certificate Policy as oid '0.4.0.194112.1.3': MAkGBwQAi+xAAQM=",
              ],
              // 'authorityKeyIdentifier' => [
              //   0 => 'Unrecognised AuthorityKeyIdentifier 0 Format: gBRzSfFAHBQEfJoSf/ovzVxnIxjpFA==',
              // ],
            ]
          ],
          'signatureAlgorithm' => 'sha512WithRSAEncryption',
          'isCA' => false
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
          'x509Version' => 3,
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
            'serialNumber' => '40f6065343c04cb671e9c8250e90ebd58dd86e55',
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
                'Certificate Policy from unknown vendor as oid \'2.5.29.32.0\': MAYGBFUdIAA='
              ]
            ]
          ],
          'signatureAlgorithm' => 'sha256WithRSAEncryption',
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
          'x509Version' => 1,
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
            'serialNumber' => '9b7e0649a33e62b9d5ee90487129ef57'
          ],
          'fingerprint' => 'eb04cf5eb1f39afa762f2bb120f296cba520c1b97db1589565b81cb9a17b7244',
          'notBefore' => 938736000,
          'notAfter' => 2099865599,
          'publicKey' => [
            'key' => $this->v1CertPublickey
          ],
          'signatureAlgorithm' => 'sha1WithRSAEncryption',
        ];
    }

    public function getTestCerts()
    {
        $this->mocrtPEM = file_get_contents(
            __DIR__ . "/certs/" . self::mocrtfile
        );
        $this->mocrt = new X509Certificate($this->mocrtPEM);
        $this->jmcrtPEM = file_get_contents(
            __DIR__ . "/certs/" . self::jmcrtfile
        );
        $this->jmcrt = new X509Certificate($this->jmcrtPEM);
        $this->eucrtPEM = file_get_contents(
            __DIR__ . "/certs/" . self::eucrtfile
        );
        $this->eucrt = new X509Certificate($this->eucrtPEM);
        $this->euissuercrtPEM = file_get_contents(
            __DIR__ . "/certs/" . self::euissuercrtfile
        );
        $this->euissuercrt = new X509Certificate($this->euissuercrtPEM);
    }

    public function testQCIssuer()
    {
        $this->getTestCerts();
        $dataDir = __DIR__.'/../data/';
        $signingCertPEM = file_get_contents(__DIR__.'/../'.LOTLRootTest::lotlSigningCertPath);
        $signingCert = new X509Certificate($signingCertPEM);
        $lotl = new TrustedList(file_get_contents($dataDir.'/eu-lotl.xml'));
        // $eucrt = new X509Certificate($this->eucrt);
        $euissuercrt = new X509Certificate($this->euissuercrt);
        // $euissuercrt->setTSPService($tspServiceAttributes);)
        $lotl->verifyTSL($signingCert);
        $testTLXML = file_get_contents(__DIR__.'/../'.TLTest::testTLXMLFileName);
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

}
