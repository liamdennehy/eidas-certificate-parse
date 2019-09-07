<?php

namespace eIDASCertificate\QCStatements;

use FG\ASN1\ASNObject;
use eIDASCertificate\OID;
use eIDASCertificate\QCStatements\QCStatementException;

/**
 *
 */
class QCRetentionPeriod extends QCStatement implements QCStatementInterface
{
    private $oid;
    private $retentionPeriod;
    const type = 'QCRetentionPeriod';

    public function __construct($statement)
    {
        $this->oid = $statement[0];
        array_shift($statement);
        if (sizeof($statement) > 1) {
            throw new QCStatementException("More than one entry in QCRetentionPeriod Statement", 1);
        } elseif (sizeof($statement) == 0) {
            throw new QCStatementException("No entries in QCRetentionPeriod Statement", 1);
        };
        $this->retentionPeriod = $statement[0]->getContent();
    }

    public function getType()
    {
        return self::type;
    }

    public function getDescription()
    {
        return "Information about the subject of this certificate will be ".
        "retained by the CA for " . $this->retentionPeriod . " years after ".
        "the certificate expiry date";
    }

    public function getURI()
    {
        return "https://www.etsi.org/deliver/etsi_en/319400_319499/31941205/02.02.01_60/en_31941205v020201p.pdf#chapter-4.3.3";
    }
}
