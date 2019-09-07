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
    const oid = '0.4.0.1862.1.4';
    private $binary;
    
    public function __construct($statements)
    {
        // $statement = $statements->getContent();
        if ($statements[0]->getContent() != self::oid) {
            throw new QCStatementException("Wrong OID for QC '" . self::type . "'", 1);
        }

        if (sizeof($statements) > 1) {
            throw new QCStatementException("More than one entry in QCSSCD Statement", 1);
        };
        $this->binary = $statements->getBinary();
    }

    public function getType()
    {
        return self::type;
    }

    public function getDescription()
    {
        return "The private key related to the certified public key resides ".
        "in a Qualified Signature/Seal Creation Device (QSCD) according to ".
        "the Regulation (EU) No 910/2014 [i.8] or a secure signature creation ".
        "device as defined in the Directive 1999/93/EC [i.3]";
    }

    public function getURI()
    {
        return "https://www.etsi.org/deliver/etsi_en/319400_319499/31941205/02.02.01_60/en_31941205v020201p.pdf#chapter-4.2.2";
    }
}
