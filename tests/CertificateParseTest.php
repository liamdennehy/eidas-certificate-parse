<?php

namespace eIDASCertificate\tests;

use PHPUnit\Framework\TestCase;
use eIDASCertificate\Certificate\X509Certificate;

class CertificateParseTest extends TestCase
{
    public function setUp()
    {
      $this->eucrt = file_get_contents(
        __DIR__ . "/certs/European-Commission.crt"
      );
    }

    public function testX509Parse()
    {
      $crt = new X509Certificate($this->eucrt);
      $crtParsed = $crt->getParsed();
      $this->assertEquals(
        '/C=BE/OU=DG CONNECT/2.5.4.97=VATBE-0949.383.342/O=European Commission/CN=EC_CNECT',
        $crtParsed['name']
      );
    }
}
