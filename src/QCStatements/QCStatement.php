<?php

namespace eIDASCertificate\QCStatements;

use eIDASCertificate\OID;
use eIDASCertificate\QCStatements\QCStatementException;

/**
 *
 */
abstract class QCStatement
{
    private $asn1Object;

    public static function fromASNObject($statements)
    {
        $statement = $statements->getContent();
        $qcStatementOID = $statement[0]->getContent();
        $qcStatementName = OID::getName($qcStatementOID);
        switch ($qcStatementName) {
        case 'qcs-QcCompliance':
          return new QCComplianceStatement($statement);
          break;
        case 'QcSSCD':
          return new QCSSCD($statement);
          break;
        case 'QcPDS':
          return new QCPDSs($statement);
          break;
        case 'QcType':
          return new QCQualifiedType($statement);
          break;
        case 'QcRetentionPeriod':
          return new QCRetentionPeriod($statement);
          break;
        case 'id-qcs-pkixQCSyntax-v2':
          return new QCSyntaxV2($statement);
          break;
        default:
          throw new QCStatementException("Unrecognised OID $qcStatementOID ($qcStatementName)", 1);
          break;
      }
    }
}
