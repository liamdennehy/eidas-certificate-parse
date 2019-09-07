<?php

namespace eIDASCertificate;

use FG\ASN1\ASNObject;
// use FG\ASN1\OID;

use eIDASCertificate\OID;
use eIDASCertificate\QCStatements\QCStatement;

/**
 *
 */
class QCStatements
{
    private $asn1Object;
    private $qcStatements;

    public function __construct($asn1Statement)
    {
        $this->asn1Object = ASNObject::fromBinary($asn1Statement);
        foreach ($this->asn1Object as $statement) {
            $this->qcStatements[] = QCStatement::fromASNObject($statement);
        }
    }

    public function getStatements()
    {
        return $this->qcStatements;
    }
}
