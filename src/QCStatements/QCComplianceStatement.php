<?php

namespace eIDASCertificate\QCStatements;

use FG\ASN1\ASNObject;
use eIDASCertificate\OID;

/**
 *
 */
class QCComplianceStatement extends QCStatement implements QCStatementInterface
{
    const type = 'QCComplianceStatement';

    public function __construct($statement)
    {
        $this->oid = $statement[0];
    }

    public function getType()
    {
        return self::type;
    }

    public function getDescription()
    {
        return "Some text about " .  self::type;
    }

    public function getURI()
    {
        return "https://www.etsi.org/deliver/etsi_en/319400_319499/31941205/02.02.01_60/en_31941205v020201p.pdf#chapter-4";
    }
}
