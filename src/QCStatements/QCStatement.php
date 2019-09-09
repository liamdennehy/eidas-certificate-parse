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
          return new QCComplianceStatement($statements);
          break;
        case 'QcLimitValue':
          return new QCLimitValue($statements->getBinary());
          break;
        case 'QcSSCD':
          return new QCSSCD($statements);
          break;
        case 'QcPDS':
          return new QCPDS($statements);
          break;
        case 'QcType':
          return new QCType($statements);
          break;
        case 'QcRetentionPeriod':
          return new QCRetentionPeriod($statements);
          break;
        case 'id-qcs-pkixQCSyntax-v2':
          return new QCSyntaxV2($statements);
          break;
        case 'PSD2':
          return new QCPSD2($statements);
          break;
        default:
          throw new QCStatementException("Unrecognised QCStatement OID $qcStatementOID ($qcStatementName)", 1);
          break;
      }
    }
}
