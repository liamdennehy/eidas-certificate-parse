<?php

namespace eIDASCertificate\QCStatements;

use FG\ASN1\ASNObject;
use eIDASCertificate\OID;

/**
 *
 */
class QCSSCD extends QCStatement implements QCStatementInterface
{
    public function __construct($statement)
    {
        if (sizeof($statement) > 1) {
            throw new QCStatementException("More than one entry in QCSSCD Statement", 1);
        };

        $this->oid = $statement[0];
    }

    public function getType()
    {
        return 'QCSSCD';
    }
}
