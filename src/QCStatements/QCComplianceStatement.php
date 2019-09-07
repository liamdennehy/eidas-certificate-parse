<?php

namespace eIDASCertificate\QCStatements;

use FG\ASN1\ASNObject;
use eIDASCertificate\OID;

/**
 *
 */
class QCComplianceStatement extends QCStatement implements QCStatementInterface
{
    const type = 'QCComplianceStatement';
    const oid = '0.4.0.1862.1.1';

    public function __construct($statement)
    {
        if ($statement[0]->getContent() != self::oid) {
            throw new QCStatementException("Wrong OID for QC '" . self::type . "'", 1);
        }
    }

    public function getType()
    {
        return self::type;
    }

    public function getDescription()
    {
        return "The certificate is an EU ".
        "qualified certificate that is issued according to Directive ".
        "1999/93/EC [i.3] or the Annex I, III or IV of the Regulation ".
        "(EU) No 910/2014 [i.8] whichever is in force at the time of issuance.";
    }

    public function getURI()
    {
        return "https://www.etsi.org/deliver/etsi_en/319400_319499/31941205/02.02.01_60/en_31941205v020201p.pdf#chapter-4";
    }
}
