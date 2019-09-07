<?php

namespace eIDASCertificate\tests;

use PHPUnit\Framework\TestCase;
use FG\ASN1\ASNObject;
use eIDASCertificate\Certificate\X509Certificate;
use eIDASCertificate\QCStatements;
use eIDASCertificate\QCStatements\QCStatement;

class QCRetentionPeriod extends TestCase
{
    public function setUp()
    {
    }

    public function testQCStatementParse()
    {
        $qcBinary = base64_decode("MAsGBgQAjkYBAwIBCg==");
        $qcObject = ASNObject::fromBinary($qcBinary);
        $qcStatement = QCStatement::fromASNObject($qcObject);
        $this->assertEquals(
            'QCRetentionPeriod',
            $qcStatement->getType()
        );
        $this->assertEquals(
            '0.4.0.1862.1.3',
            $qcObject->getContent()[0]->getContent()
        );
    }
}
