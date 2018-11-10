<?php

namespace eIDASCertificate\tests;

use PHPUnit\Framework\TestCase;

;
use PSD2Certificate\Parser;

class ParserTest extends TestCase
{
    public function testParseX509()
    {
        $pem = file_get_contents(getenv("TPPCERT"));
        $x509 = new Parser($pem);
        $this->assertEquals('v3', $x509->DumpCert()['version']);
    }
}
