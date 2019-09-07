<?php

namespace eIDASCertificate\tests;

use PHPUnit\Framework\TestCase;
use eIDASCertificate\Certificate\X509Certificate;

class CertificateParseTest extends TestCase
{
    const jmcrtfile = 'Jean-Marc Verbergt (Signature).crt';
    const mocrtfile = 'Maarten Joris Ottoy.crt';
    const eucrtfile = 'European-Commission.crt';

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

    public function testX509Parse()
    {
        $crtParsed = $this->eucrt->getParsed();
        $this->assertEquals(
            '/C=BE/OU=DG CONNECT/2.5.4.97=VATBE-0949.383.342'.
            '/O=European Commission/CN=EC_CNECT',
            $crtParsed['name']
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
            ['C' => 'BE',
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
        $crtParsed = $this->jmcrt->getParsed();
        $this->assertEquals(
            '/C=BE/CN=Jean-Marc Verbergt (Signature)/SN=Verbergt/GN=Jean-Marc/serialNumber=67022330340',
            $crtParsed['name']
        );
    }

    public function testX509Extensions()
    {
        $this->assertTrue($this->eucrt->hasExtensions()) ;
        $this->assertTrue($this->jmcrt->hasExtensions()) ;
    }

    public function testX509hasQCStatements()
    {
        $this->assertTrue($this->eucrt->hasQCStatements()) ;
        $this->assertTrue($this->jmcrt->hasQCStatements()) ;
    }
}
