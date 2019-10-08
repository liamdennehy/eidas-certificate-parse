<?php

namespace eIDASCertificate\QCStatements;

use eIDASCertificate\OID;
use ASN1\Type\UnspecifiedType;

/**
 *
 */
class QCCompliance extends QCStatement implements QCStatementInterface
{
    private $binary;

    const type = 'QCCompliance';
    const oid = '0.4.0.1862.1.1';

    public function __construct($qcStatementDER, $isCritical = false)
    {
        $qcStatement = UnspecifiedType::fromDER($qcStatementDER)->asSequence();
        $this->binary = $qcStatementDER;
    }

    public function getType()
    {
        return self::type;
    }

    public function getDescription()
    {
        return "The certificate is an EU ".
        "qualified certificate that is issued according to Directive ".
        "1999/93/EC or the Annex I, III or IV of the Regulation ".
        "(EU) No 910/2014 whichever is in force at the time of issuance.";
    }

    public function getURI()
    {
        return "https://www.etsi.org/deliver/etsi_en/319400_319499/31941205/02.02.01_60/en_31941205v020201p.pdf#chapter-4.2.1";
    }

    public function getBinary()
    {
        return $this->binary;
    }

    public function getFindings()
    {
        return [];
    }

    public function getIsCritical()
    {
        return false;
    }

    public function setCertificate()
    {
        null;
    }

    public function getAttributes()
    {
        return [];
    }
}
