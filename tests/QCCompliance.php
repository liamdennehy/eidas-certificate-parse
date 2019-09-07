<?php

namespace eIDASCertificate\tests;

use PHPUnit\Framework\TestCase;
use FG\ASN1\ASNObject;
use eIDASCertificate\Certificate\X509Certificate;
use eIDASCertificate\QCStatements;
use eIDASCertificate\QCStatements\QCStatement;

class QCCompliance extends TestCase
{
    public function setUp()
    {
    }

    public function testQCStatementParse()
    {
        $qcBinary = base64_decode('MAgGBgQAjkYBAQ==');
        $qcObject = ASNObject::fromBinary($qcBinary);
        $qcStatement = QCStatement::fromASNObject($qcObject);
        $this->assertEquals(
            'QCComplianceStatement',
            $qcStatement->getType()
        );
        $this->assertEquals(
            '0.4.0.1862.1.1',
            $qcObject->getContent()[0]->getContent()
        );
    }
}
