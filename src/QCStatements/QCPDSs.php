<?php

namespace eIDASCertificate\QCStatements;

use FG\ASN1\ASNObject;
use eIDASCertificate\OID;
use eIDASCertificate\QCStatements\QCStatementException;

/**
 *
 */
class QCPDSs extends QCStatement
{
    private $oid;
    private $pdsLocations;

    public function __construct($statement)
    {
        $this->oid = $statement[0];
        array_shift($statement);
        if (sizeof($statement) > 1) {
            throw new QCStatementException("More than one entry in PDS Statement", 1);
        } elseif (sizeof($statement) == 0) {
            throw new QCStatementException("No entries in PDS Statement", 1);
        };
        foreach ($statement[0] as $value) {
            $location['url'] = (string)$value[0];
            $location['language'] = (string)$value[1];
            $this->pdsLocations[] = $location;
        }
    }
}
