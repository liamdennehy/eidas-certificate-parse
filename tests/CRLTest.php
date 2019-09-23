<?php

namespace eIDASCertificate\tests;

use PHPUnit\Framework\TestCase;
use eIDASCertificate\Certificate\X509Certificate;
use eIDASCertificate\DataSource;

class CRLTest extends TestCase
{
    const jmcrtfile = 'Jean-Marc Verbergt (Signature).crt';

    public function setUp()
    {
        $this->datadir = __DIR__ . '/../data';
    }

    public function testX509Parse()
    {
        $jmcrt = new X509Certificate(
            file_get_contents(
              __DIR__ . "/certs/" . self::jmcrtfile
          )
        );
        $crlURI = $jmcrt->getCDPs()[0];
        $crlURIId = hash('sha256', $crlURI);
        $crlFilePath = $this->datadir.'/'.$crlURIId.'.crl';
        // var_dump([$crlFilePath, file_exists($crlFilePath)]); exit;
        if (! file_exists($crlFilePath)) {
            $crlData = DataSource::getHTTP($crlURI);
            file_put_contents($crlFilePath, $crlData);
        } else {
            $crlData = file_get_contents($crlFilePath);
        }

        $jmcrt->withCRL($crlData);
        // exit;
        $this->assertFalse(
            $jmcrt->isRevoked()
        );
        $this->assertTrue(
            $jmcrt->getCRL()->getCount() > 60000
        );
    }
}
