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
        $this->qcStatements = [];
        $this->asn1Object = ASNObject::fromBinary($asn1Statement);
        foreach ($this->asn1Object as $statement) {
            $qcStatement = QCStatement::fromASNObject($statement);
            if (array_key_exists($qcStatement->getType(), $this->qcStatements)) {
                throw new QCStatementException(
                    "Multiple QCStatements of type " . $qcStatement->getType(),
                    1
                );
            }
            $this->qcStatements[$qcStatement->getType()] = $qcStatement;
        }
    }

    public function getStatements()
    {
        return $this->qcStatements;
    }
}
