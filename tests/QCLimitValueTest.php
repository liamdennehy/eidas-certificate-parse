<?php

namespace eIDASCertificate\tests;

use PHPUnit\Framework\TestCase;
use FG\ASN1\ASNObject;
use eIDASCertificate\QCStatements\QCStatement;

class QCLimitValueTest extends TestCase
{
    public function setUp()
    {
    }

    public function testQCLimitValue()
    {
        $qcBinary = base64_decode("MBUGBgQAjkYBAjALEwNIVUYCAQUCAQY=");
        $qcObject = ASNObject::fromBinary($qcBinary);
        $qcStatement = QCStatement::fromASNObject($qcObject);
        $this->assertEquals(
            '0.4.0.1862.1.2',
            $qcObject->getContent()[0]->getContent()
        );
        $this->assertEquals(
            'QcLimitValue',
            $qcStatement->getType()
        );
        $this->assertEquals(
            [
              'currency' => 'HUF',
              'amount' => '5',
              'exponent' => '6'
            ],
            $qcStatement->getLimit()
        );
    }
}
