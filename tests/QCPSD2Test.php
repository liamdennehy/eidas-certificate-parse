<?php

namespace eIDASCertificate\tests;

use PHPUnit\Framework\TestCase;
use FG\ASN1\ASNObject;
use eIDASCertificate\QCStatements\QCStatement;

class QCPSD2Test extends TestCase
{
    public function setUp()
    {
    }

    public function testPSD2QCStatement()
    {
        $qcBinary = base64_decode(
            'MEgGBgQAgZgnAjA+MCYwEQYHBACBmCcBAQwGUFNQX0FTMBEGBwQAgZgnAQIMBlBTU'.
            'F9QSQwNQmFuayBvZiBTcGFpbgwFRVMtQkU='
        );
        $qcObject = ASNObject::fromBinary($qcBinary);
        $qcStatement = QCStatement::fromASNObject($qcObject);
        $this->assertEquals(
            'QCPSD2',
            $qcStatement->getType()
        );
        $this->assertEquals(
            ['roles' => [
                'PSP_AS',
                'PSP_PI'
              ],
              'NCAShortName' => 'ES-BE',
              'NCALongName' => 'Bank of Spain'
            ],
            $qcStatement->getAuthorisations()
        );
    }
}
