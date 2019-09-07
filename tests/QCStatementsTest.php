<?php

namespace eIDASCertificate\tests;

use PHPUnit\Framework\TestCase;
use eIDASCertificate\Certificate\X509Certificate;
use eIDASCertificate\QCStatements;
use eIDASCertificate\QCStatements\QCStatement;

class qcStatementsTest extends TestCase
{
    const jmcrtfile = 'Jean-Marc Verbergt (Signature).crt';
    const eucrtfile = 'European-Commission.crt';

    public function setUp()
    {
        $this->jmcrt = new X509Certificate(
          file_get_contents(
            __DIR__ . "/certs/" . self::jmcrtfile
        )
      );
        $this->eucrt = new X509Certificate(
          file_get_contents(
            __DIR__ . "/certs/" . self::eucrtfile
        )
      );
    }

    public function testQCStatementsParse()
    {
        $crtParsed = $this->eucrt->getParsed();
        $qcStatementBinary =
          $crtParsed['extensions']['qcStatements'];
        $qcStatements = new QCStatements($qcStatementBinary);
        $this->assertEquals(
          5,
          sizeof($qcStatements->getStatements())
      );

        $crtParsed = $this->jmcrt->getParsed();
        $qcStatementBinary =
          $crtParsed['extensions']['qcStatements'];
        $qcStatements = new QCStatements($qcStatementBinary);
        $this->assertEquals(
          2,
          sizeof($qcStatements->getStatements())
      );
    }
}
