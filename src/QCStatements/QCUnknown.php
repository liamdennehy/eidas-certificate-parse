<?php

namespace eIDASCertificate\QCStatements;

use eIDASCertificate\OID;
use ASN1\Type\UnspecifiedType;

/**
 *
 */
class QCUnknown extends QCStatement implements QCStatementInterface
{
    private $binary;
    private $oid;

    const type = 'unknown';

    public function __construct($qcStatementDER, $oid)
    {
        $this->oid = $oid;
        $this->binary = $qcStatementDER;
    }

    public function getType()
    {
        return self::type .'-'. $this->oid;
    }

    public function getDescription()
    {
        return "QCStatement with OID $this->oid is not recognised";
    }

    public function getURI()
    {
        return "";
    }

    public function getBinary()
    {
        return $this->binary;
    }
}
