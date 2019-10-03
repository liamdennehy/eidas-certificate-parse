<?php

namespace eIDASCertificate\QCStatements;

use eIDASCertificate\OID;
use ASN1\Type\UnspecifiedType;

/**
 *
 */
class QCSSCD extends QCStatement implements QCStatementInterface
{
    private $binary;

    const type = 'QCSSCD';
    const oid = '0.4.0.1862.1.4';

    public function __construct($qcStatementDER, $isCritical = false)
    {
        $qcStatement = UnspecifiedType::fromDER($qcStatementDER)->asSequence();
        $this->binary = $qcStatement->toDER();
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
}
