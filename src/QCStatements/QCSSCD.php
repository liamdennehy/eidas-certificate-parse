<?php

namespace eIDASCertificate\QCStatements;

use FG\ASN1\ASNObject;
use eIDASCertificate\OID;

// use eIDASCertificate\OID => LocalOIDs;

/**
 *
 */
class QCSSCD extends QCStatement
{
    public function __construct($statement)
    {
        $this->oid = $statement[0];
    }
}
