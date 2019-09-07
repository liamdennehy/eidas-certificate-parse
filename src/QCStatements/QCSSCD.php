<?php

namespace eIDASCertificate\QCStatements;

use FG\ASN1\ASNObject;
use eIDASCertificate\OID;

/**
 *
 */
class QCSSCD extends QCStatement implements QCStatementInterface
{
    const type = 'QCSSCD';

    public function __construct($statement)
    {
        if (sizeof($statement) > 1) {
            throw new QCStatementException("More than one entry in QCSSCD Statement", 1);
        };

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
        return "https://www.etsi.org/deliver/etsi_en/319400_319499/31941205/02.02.01_60/en_31941205v020201p.pdf#chapter-4.2.2";
    }
}
