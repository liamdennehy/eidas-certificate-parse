<?php

namespace eIDASCertificate\tests;

use PHPUnit\Framework\TestCase;
use eIDASCertificate\Certificate\X509Certificate;
use eIDASCertificate\DataSource;

class CRLTest extends TestCase
{
    const jmcrtfile = 'Jean-Marc Verbergt (Signature).crt';
    const eucrtfile = 'European-Commission.crt';

    public function setUp()
    {
        $this->datadir = __DIR__ . '/../data';
    }

    public function testX509Parse()
    {
        $eucrt = new X509Certificate(
            file_get_contents(
                __DIR__ . "/certs/" . self::eucrtfile
            )
        );

        $crlURI = $eucrt->getCDPs()[0];
        $crlURIId = hash('sha256', $crlURI);
        $crlFilePath = $this->datadir.'/'.$crlURIId.'.crl';
        if (! file_exists($crlFilePath)) {
            $crlData = DataSource::getHTTP($crlURI);
            file_put_contents($crlFilePath, $crlData);
        } else {
            $crlData = file_get_contents($crlFilePath);
        }

        $eucrt->withCRL($crlData);
        // exit;
        $this->assertFalse(
            $eucrt->isRevoked()
        );
        $this->assertEquals(
            [
            '502164680748718126229572676998261192453463359302',
            '44802405597337679806284414787175963970124562034',
            '493426603787953254575369944823793415078738475825',
            '131347927415174182309564338619337891206250712126',
            '275942328671361560927880637658069302925839493090'
          ],
            array_slice($eucrt->getCRL()->getRevokedSerials(), 0, 5)
        );
    }
}
