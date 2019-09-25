<?php

namespace eIDASCertificate\tests;

use PHPUnit\Framework\TestCase;
use eIDASCertificate\Certificate\CertificateRevocationList;
use eIDASCertificate\Certificate\X509Certificate;
use eIDASCertificate\DataSource;

class CRLTest extends TestCase
{
    const eucrtfile = 'European-Commission.crt';
    const eucrlpath = 'http://crl.quovadisglobal.com/qvbecag2.crl';

    public function setUp()
    {
        $this->datadir = __DIR__ . '/../data';
    }

    public function testCRLParse()
    {
        $eucrt = new X509Certificate(
            file_get_contents(
                __DIR__ . "/certs/" . self::eucrtfile
            )
        );

        $crlURIId = hash('sha256', self::eucrlpath);
        $crlFilePath = $this->datadir.'/'.$crlURIId.'.crl';
        if (! file_exists($crlFilePath)) {
            $crlData = DataSource::getHTTP($crlURI);
            file_put_contents($crlFilePath, $crlData);
        } else {
            $crlData = file_get_contents($crlFilePath);
        }

        $testTime = new \DateTime('@1569225604');
        $eucrl = new CertificateRevocationList($crlData);
        $this->assertEquals(
            ['1569222004','1569481204'],
            [
            $eucrl->getDates()['thisUpdate']->format('U'),
            $eucrl->getDates()['nextUpdate']->format('U')
          ]
        );
        $this->assertEquals(
            [
            true,
            true
          ],
            [
            $eucrl->isStartedAt($testTime),
            $eucrl->isNotFinishedAt($testTime)
          ]
        );
        $this->assertTrue($eucrl->isCurrentAt(new \DateTime('@1569225604')));
        $eucrt->withCRL($crlData);
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
