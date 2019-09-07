<?php

namespace eIDASCertificate\QCStatements;

use FG\ASN1\ASNObject;
use eIDASCertificate\OID;
use eIDASCertificate\QCStatements\QCStatementException;

/**
 *
 */
class QCPDSs extends QCStatement implements QCStatementInterface
{
    private $oid;
    private $pdsLocations;
    const type = 'QCPDSs';

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
        return "https://www.etsi.org/deliver/etsi_en/319400_319499/31941205/02.02.01_60/en_31941205v020201p.pdf#chapter-4.3.4";
    }
}
