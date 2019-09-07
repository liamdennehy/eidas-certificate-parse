<?php

namespace eIDASCertificate\QCStatements;

use FG\ASN1\ASNObject;
use eIDASCertificate\OID;

/**
 *
 */
class QCComplianceStatement extends QCStatement implements QCStatementInterface
{
    public function __construct($statement)
    {
        $this->oid = $statement[0];
    }

    public function getType()
    {
        return 'QCComplianceStatement';
    }
}
