<?php

namespace eIDASCertificate\QCStatements;

use eIDASCertificate\OID;
use eIDASCertificate\QCStatements\QCStatementException;
use ASN1\Type\UnspecifiedType;

/**
 *
 */
class QCType extends QCStatement implements QCStatementInterface
{
    private $qcType;
    const type = 'QCQualifiedType';
    const oid = '0.4.0.1862.1.6';

    public function __construct($qcStatementDER)
    {
        $qcStatement = UnspecifiedType::fromDER($qcStatementDER)->asSequence();
        if ($qcStatement->at(0)->asObjectIdentifier()->oid() != self::oid) {
            throw new QCStatementException("Wrong OID for QC '" . self::type . "'", 1);
        }

        if ($qcStatement->count() > 2) {
            throw new QCStatementException("More than one entry in QCType Statement", 1);
        } elseif ($qcStatement->count() < 2) {
            throw new QCStatementException("No entries in QCType Statement", 1);
        };
        $qcTypes = $qcStatement->at(1)->asSequence();
        if ($qcTypes->count() > 1) {
            throw new QCStatementException("Multiple QCTypes not supported", 1);
        }
        $qcTypeOID = $qcTypes->at(0)->asObjectIdentifier()->oid();
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
        $this->binary = $qcStatementDER;
    }

    public function getType()
    {
        return self::type;
    }

    public function getQCType()
    {
        return $this->qcType;
    }

    public function getDescription()
    {
        switch ($this->qcType) {
          case 'esign':
            return "Certificate for Electronic Signatures";
            break;
          case 'eseal':
            return "Certificate for Electronic Seals";
            break;
          case 'web':
            return "Certificate for Website Authentication";
            break;

          default:
          throw new QCStatementException("Cannot describe QCType OID ".self::oid." (".$this->qcType.")", 1);

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
