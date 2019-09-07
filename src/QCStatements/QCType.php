<?php

namespace eIDASCertificate\QCStatements;

use FG\ASN1\ASNObject;
use eIDASCertificate\OID;
use eIDASCertificate\QCStatements\QCStatementException;

/**
 *
 */
class QCType extends QCStatement implements QCStatementInterface
{
    private $qcType;
    const type = 'QCQualifiedType';
    const oid = '0.4.0.1862.1.6';

    public function __construct($statements)
    {
        $statement = $statements->getContent();
        if ($statement[0]->getContent() != self::oid) {
            throw new QCStatementException("Wrong OID for QC '" . self::type . "'", 1);
        }
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
          case 'web':
            $this->qcType = $qcTypeName;
            break;

          default:
            throw new QCStatementException("Unrecognised QCType OID $qcTypeOID ($qcTypeName)", 1);
            break;
        }
    }

    public function getType()
    {
        return self::type .'-'.$this->qcType;
    }

    public function getDescription()
    {
        switch ($this->qcType) {
          // case 'esign':
          //   return "CERTIFICATES FOR ELECTRONIC SIGNATURES";
          //   break;

          default:
          throw new QCStatementException("Unrecognised QCType OID ".self::oid." (".$this->qcType.")", 1);

            break;
        }
        return self::oid . " Some text about " .  self::type;
    }

    public function getURI()
    {
        return "https://www.etsi.org/deliver/etsi_en/319400_319499/31941205/02.02.01_60/en_31941205v020201p.pdf#chapter-4.2.3";
    }

    public function getBinary()
    {
        return $this->binary;
    }
}
