<?php

namespace eIDASCertificate;

use FG\ASN1\ASNObject;
use eIDASCertificate\OID;

/**
 *
 */
class QCComplianceStatement extends QCStatement
{
    public function __construct($statement)
    {
        $this->oid = $statement[0];
    }
}
