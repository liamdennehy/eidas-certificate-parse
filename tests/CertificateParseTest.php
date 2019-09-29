<?php

namespace eIDASCertificate\tests;

use PHPUnit\Framework\TestCase;
use eIDASCertificate\Certificate\X509Certificate;
use ASN1\Type\UnspecifiedType;

class CertificateParseTest extends TestCase
{
    const jmcrtfile = 'Jean-Marc Verbergt (Signature).crt';
    const mocrtfile = 'Maarten Joris Ottoy.crt';
    const eucrtfile = 'European-Commission.crt';

    public function setUp()
    {
        $this->testTime = new \DateTime('@1569225604');
        $this->eucrtAttributes =
        [
          'subject' => '/C=BE/OU=DG CONNECT/2.5.4.97=VATBE-0949.383.342/O=European Commission/CN=EC_CNECT',
          'fingerprint' => 'ccd879b36bb553685becbd12901c7f41f7bd3e07f898fcbbe1eec456b03d7589',
          'SKIHex' => 'e811fc46be23b48f3ef7b1d778df0997b8ec4524',
          'SKIBase64' => '6BH8Rr4jtI8+97HXeN8Jl7jsRSQ=',
          'AKIHex' => '87c9bc3197127a73bb7ec03d4551b401259551ab',
          'AKIBase64' => 'h8m8MZcSenO7fsA9RVG0ASWVUas='
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
    }

    public function testX509Parse()
    {
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
    }

    public function testX509Atrributes()
    {
        $this->getTestCerts();
        $this->assertEquals(
            $this->eucrtAttributes,
            $this->eucrt->gatAttributes()
        );
    }
}
