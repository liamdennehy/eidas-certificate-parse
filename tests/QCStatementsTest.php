<?php

namespace eIDASCertificate\tests;

use PHPUnit\Framework\TestCase;
use eIDASCertificate\Certificate\X509Certificate;
use eIDASCertificate\Extensions\QCStatements;
use eIDASCertificate\QCStatements\QCCompliance;
use eIDASCertificate\QCStatements\QCLimitValue;
use eIDASCertificate\QCStatements\QCRetentionPeriod;
use eIDASCertificate\QCStatements\QCPDS;
use eIDASCertificate\QCStatements\QCPSD2;
use eIDASCertificate\QCStatements\QCSSCD;
use eIDASCertificate\QCStatements\QCSyntaxV2;
use eIDASCertificate\QCStatements\QCType;

class QCStatementsTest extends TestCase
{
    const jmcrtfile = 'Jean-Marc Verbergt (Signature).crt';
    const eucrtfile = 'European-Commission.crt';
    const mocrtfile = 'Maarten Joris Ottoy.crt';
    const QCComplianceBaseDescription =
      'The certificate is an EU qualified certificate that is issued '.
      'according to Directive 1999/93/EC or the Annex I, III or IV of the '.
      'Regulation (EU) No 910/2014 whichever is in force at the time of '.
      'issuance.';
    const QCComplianceESDDescription =
      'The certificate is an EU qualified certificate that is issued '.
      'according to Directive 1999/93/EC';
    const QCComplianceeIDASDescription =
      'The certificate is an EU qualified certificate that is issued '.
      'according to Annex I, III or IV of the Regulation (EU) No 910/2014.';
    const QCSSCDBaseDescription =
      'The private key related to the certified public key resides in a '.
      'Qualified Signature/Seal Creation Device (QSCD) according to the '.
      'Regulation (EU) No 910/2014 or a secure signature creation '.
      'device as defined in the Directive 1999/93/EC';
    const QCSSCDESDDescription =
      'The private key related to the certified public key resides '.
      'in a secure signature creation '.
      'device as defined in the Directive 1999/93/EC';
    const QCSSCDeIDASDescription =
      'The private key related to the certified public key resides in a '.
      'Qualified Signature/Seal Creation Device (QSCD) according to the '.
      'Regulation (EU) No 910/2014';

    public function setUp()
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
    }

    public function testQCCompliance()
    {
        $qcBinary = base64_decode('MAgGBgQAjkYBAQ==');
        $qcCompliance = new QCCompliance($qcBinary);
        $this->assertEquals(
            '99b818e96263d013819f99c0ec5c4b426c0dbbf8389309b86a02e641208adb95',
            hash('sha256', $qcCompliance->getDescription())
        );
        $this->assertEquals(
            self::QCComplianceBaseDescription,
            $qcCompliance->getDescription()
        );
        $qcCompliance->setCertificate($this->jmcrt);
        $this->assertEquals(
            self::QCComplianceESDDescription,
            $qcCompliance->getDescription()
        );
        $qcCompliance->setCertificate($this->eucrt);
        $this->assertEquals(
            self::QCComplianceeIDASDescription,
            $qcCompliance->getDescription()
        );
    }

    public function testQCLimitValue()
    {
        $qcBinary = base64_decode("MBUGBgQAjkYBAjALEwNIVUYCAQUCAQY=");
        $qcLimitValue = new QCLimitValue($qcBinary);
        $this->assertEquals(
            [
            'currency' => 'HUF',
            'amount' => '5',
            'exponent' => '6'
          ],
            $qcLimitValue->getLimit()
        );
        $this->assertEquals(
            'This certificate is authorised for transactions up to 5,000,000 units of currency HUF',
            $qcLimitValue->getDescription()
        );
    }

    public function testQCPDS()
    {
        $binary = base64_decode(
            'MEgGBgQAjkYBBTA+MDwWNmh0dHBzOi8vd3d3Lmx1eHRydXN0Lmx1L3VwbG9hZC9k'.
            'YXRhL3JlcG9zaXRvcnkvUERTLnBkZhMCRU4='
        );
        $qcPDS = new QCPDS($binary);
        $this->assertEquals(
            [
              0 => [
                [
                  'url' =>
                      'https://www.luxtrust.lu/upload/data/repository/PDS.pdf',
                  'language' => 'en'
                ]
              ]
            ],
            [
              $qcPDS->getLocations()
            ]
        );
        $binary = base64_decode(
            'MFMGBgQAjkYBBTBJMCQWHmh0dHBzOi8vY3AuZS1zemlnbm8uaHUvcWNwc19lbhMC'.
            'ZW4wIRYbaHR0cHM6Ly9jcC5lLXN6aWduby5odS9xY3BzEwJodQ=='
        );
        $qcPDS = new QCPDS($binary);
        $this->assertEquals(
            [
            0 => [
                'url' => 'https://cp.e-szigno.hu/qcps_en',
                'language' => 'en'
            ],
            1 => [
                'url' => 'https://cp.e-szigno.hu/qcps',
                'language' => 'hu'
            ]],
            $qcPDS->getLocations()
        );
    }

    public function testQPSD2()
    {
        $qcBinary = base64_decode(
            'MHkGBgQAgZgnAjBvMDkwEQYHBACBmCcBAgwGUFNQX1BJMBEGBwQAgZgnAQMMBlBT'.
            'UF9BSTARBgcEAIGYJwEEDAZQU1BfSUMMJ0Zpbm5pc2ggRmluYW5jaWFsIFN1cGVy'.
            'dmlzb3J5IEF1dGhvcml0eQwJRkktRklORlNB'
        );
        $qcPSD2Statement = new QCPSD2($qcBinary);
        $this->assertEquals(
            'QCPSD2',
            $qcPSD2Statement->getType()
        );
        $this->assertEquals(
            [
              'roles' => [
                'PSP_PI',
                'PSP_AI',
                'PSP_IC'
              ],
              'NCAShortName' => 'FI-FINFSA',
              'NCALongName' => 'Finnish Financial Supervisory Authority'
            ],
            $qcPSD2Statement->getAuthorisations()
        );
        $qcBinary = base64_decode(
            'MEgGBgQAgZgnAjA+MCYwEQYHBACBmCcBAQwGUFNQX0FTMBEGBwQAgZgnAQIMBlBTU'.
        'F9QSQwNQmFuayBvZiBTcGFpbgwFRVMtQkU='
        );
        $qcPSD2Statement = new QCPSD2($qcBinary);
        $this->assertEquals(
            [
              'roles' => [
                'PSP_AS',
                'PSP_PI'
              ],
              'NCAShortName' => 'ES-BE',
              'NCALongName' => 'Bank of Spain'
            ],
            $qcPSD2Statement->getAuthorisations()
        );
    }

    public function testQCRetentionPeriod()
    {
        $binary = base64_decode('MAsGBgQAjkYBAwIBCg==');
        $qcRetentionPeriod = new QCRetentionPeriod($binary);
        $this->assertEquals(
            10,
            $qcRetentionPeriod->getRetentionPeriodYears()
        );
        $this->assertEquals(
          'Information about the subject of this certificate will be retained '.
          'by the CA for 10 years after the certificate expiry date',
          $qcRetentionPeriod->getDescription()
        );
        $this->assertEquals(
          ['subjectDataRetention' => '10 year(s)'],
          $qcRetentionPeriod->getAttributes()
        );
    }

    public function testQCSSCD()
    {
        $binary = base64_decode('MAgGBgQAjkYBBA==');
        $qcSSCD = new QCSSCD($binary);
        $this->assertEquals(
            self::QCSSCDBaseDescription,
            $qcSSCD->getDescription()
        );
        $qcSSCD->setCertificate($this->jmcrt);
        $this->assertEquals(
            self::QCSSCDESDDescription,
            $qcSSCD->getDescription()
        );
        $qcSSCD->setCertificate($this->eucrt);
        $this->assertEquals(
            self::QCSSCDeIDASDescription,
            $qcSSCD->getDescription()
        );
    }

    public function testQCSyntaxV2()
    {
        $binary = base64_decode('MBUGCCsGAQUFBwsCMAkGBwQAi+xJAQI=');
        $qcSyntaxV2 = new QCSyntaxV2($binary);
        $this->assertEquals(
            'LegalPerson',
            $qcSyntaxV2->getSemanticsType()
        );
    }

    public function testQCType()
    {
        $binary = base64_decode('MBMGBgQAjkYBBjAJBgcEAI5GAQYC');
        $qcType = new QCType($binary);
        $this->assertEquals(
            'eseal',
            $qcType->getQCType()
        );
        $binary = base64_decode('MBMGBgQAjkYBBjAJBgcEAI5GAQYB');
        $qcType = new QCType($binary);
        $this->assertEquals(
            'esign',
            $qcType->getQCType()
        );
    }

    public function testQCStatementsParse()
    {
        $der=base64_decode(
            'MH0wFQYIKwYBBQUHCwIwCQYHBACL7EkBAjAIBgYEAI5GAQEwCAYGBACORgEEMBMGBg'.
            'QAjkYBBjAJBgcEAI5GAQYCMDsGBgQAjkYBBTAxMC8WKWh0dHBzOi8vd3d3LnF1b3Zh'.
            'ZGlzZ2xvYmFsLmNvbS9yZXBvc2l0b3J5EwJlbg=='
        );
        // $this->getTestCerts();
        $qcStatements = new QCStatements($der);
        $this->assertEquals(
            [
              'QCSyntaxV2',
              'QCCompliance',
              'QCSSCD',
              'QCQualifiedType',
              'QCPDS'
            ],
            array_keys($qcStatements->getStatements())
        );
        $this->assertEquals(
            'eseal',
            $qcStatements->getQCType()
        );

        $der=base64_decode(
            'MBQwCAYGBACORgEBMAgGBgQAjkYBBA=='
        );
        $qcStatements = new QCStatements($der);
        $this->assertEquals(
            [
              'QCCompliance',
              'QCSSCD'
            ],
            array_keys($qcStatements->getStatements())
        );
    }
}
