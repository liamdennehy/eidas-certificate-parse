<?php

namespace eIDASCertificate\QCStatements;

use FG\ASN1\ASNObject;
use eIDASCertificate\OID;
use eIDASCertificate\QCStatements\QCStatementException;

/**
 *
 */
class QCQualifiedType extends QCStatement
{
    private $qcType;

    public function __construct($statement)
    {
        $this->oid = $statement[0];
        array_shift($statement);
        if (sizeof($statement) > 1) {
            throw new QCStatementException("More than one entry in QCType Statement", 1);
        } elseif (sizeof($statement) == 0) {
            throw new QCStatementException("No entries in QCType Statement", 1);
        };
        if (sizeof($statement[0]) > 1) {
            throw new QCStatementException("More than one QCType in Statement", 1);
        } elseif (sizeof($statement[0]) == 0) {
            throw new QCStatementException("No entries in QCType in Statement", 1);
        };
        $qcTypeOID = $statement[0][0]->getContent();
        $qcTypeName = OID::getName($qcTypeOID);
        switch ($qcTypeName) {
      case 'esign':
      case 'eseal':
        $this->qcType = $qcTypeName;
        break;

      default:
        throw new QCStatementException("Unrecognised QCType OID $qcTypeOID ($qcTypeName)", 1);
        break;
    }
    }
}
