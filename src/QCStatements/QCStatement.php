<?php

namespace eIDASCertificate\QCStatements;

use eIDASCertificate\OID;
use eIDASCertificate\QCStatements\QCStatementException;
use ASN1\Type\UnspecifiedType;

/**
 *
 */
abstract class QCStatement
{
    private $asn1Object;

    public static function fromBinary($qcStatementDER)
    {
        $qcStatement = UnspecifiedType::fromDER($qcStatementDER)->asSequence();
        $qcStatementOID = $qcStatement->at(0)->asObjectIdentifier()->oid();
        $qcStatementName = OID::getName($qcStatementOID);
        switch ($qcStatementName) {
        case 'QcCompliance':
          return new QCCompliance($qcStatementDER);
          break;
        case 'QcLimitValue':
          return new QCLimitValue($qcStatementDER);
          break;
        case 'QcSSCD':
          return new QCSSCD($qcStatementDER);
          break;
        case 'QcPDS':
          return new QCPDS($qcStatementDER);
          break;
        case 'QcType':
          return new QCType($qcStatementDER);
          break;
        case 'QcRetentionPeriod':
          return new QCRetentionPeriod($qcStatementDER);
          break;
        case 'id-qcs-pkixQCSyntax-v2':
          return new QCSyntaxV2($qcStatementDER);
          break;
        case 'PSD2':
          return new QCPSD2($qcStatementDER);
          break;
        default:
          $qcStatement = new QCUnknown($qcStatementDER, $qcStatementOID);
          $qcStatement->setOID($qcStatementOID);
          return $qcStatement;
          break;
      }
    }
}
