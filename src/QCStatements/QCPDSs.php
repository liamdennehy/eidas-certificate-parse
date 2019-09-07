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
    private $pdsLocations;
    const type = 'QCPDSs';
    const oid = '0.4.0.1862.1.5';

    public function __construct($statements)
    {
        $statement = $statements->getContent();
        if ($statement[0]->getContent() != self::oid) {
            throw new QCStatementException("Wrong OID for QC '" . self::type . "'", 1);
        }
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
        $this->binary = $statements->getBinary();
    }

    public function getLocations()
    {
        return $this->pdsLocations;
    }

    public function getType()
    {
        return self::type;
    }

    public function getDescription()
    {
        return "This QCStatement holds URLs to PKI Disclosure Statements (PDS)";
    }

    public function getURI()
    {
        return "https://www.etsi.org/deliver/etsi_en/319400_319499/31941205/02.02.01_60/en_31941205v020201p.pdf#chapter-4.3.4";
    }

    public function getBinary()
    {
        return $this->binary;
    }
}
