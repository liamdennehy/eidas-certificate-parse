<?php

namespace eIDASCertificate\QCStatements;

use eIDASCertificate\OID;
use ASN1\Type\UnspecifiedType;

/**
 *
 */
class QCSyntaxV2 extends QCStatement implements QCStatementInterface
{
    const type = 'QCSyntaxV2';
    const oid = '1.3.6.1.5.5.7.11.2';
    const uri = 'https://www.etsi.org/deliver/etsi_en/319400_319499/31941201/01.01.01_60/en_31941201v010101p.pdf#chapter-5.1';

    private $semanticsType;

    public function __construct($qcStatementDER)
    {
        $qcStatement = UnspecifiedType::fromDER($qcStatementDER)->asSequence();

        if ($qcStatement->at(0)->asObjectIdentifier()->oid() != self::oid) {
            throw new QCStatementException("Wrong OID for QC '" . self::type . "'", 1);
        }
        if ($qcStatement->count() < 2) {
            $this->semanticsType = 'notProvided';
        // throw new QCStatementException("No QCSyntaxV2 Statements found: ".base64_encode($qcStatementDER), 1);
        } elseif ($qcStatement->count() > 2) {
            throw new QCStatementException("More than one entry in QCSyntaxV2 Statement", 1);
        } else {
            $semanticsTypeOID = $qcStatement->at(1)->asSequence()->at(0)->asObjectIdentifier()->oid();
            switch ($semanticsTypeOID) {
            case '0.4.0.194121.1.2':
            $this->semanticsType = 'LegalPerson';
            break;
            case '0.4.0.194121.1.1':
            $this->semanticsType = 'NaturalPerson';
            break;
            default:
            throw new QCStatementException("QCSyntaxV2 statement '$semanticsType' not yet implemented");
            break;
          }
        }
        $this->binary = $qcStatementDER;
    }

    public function getType()
    {
        return self::type;
    }

    public function getSemanticsType()
    {
        return $this->semanticsType;
    }

    public function getDescription()
    {
        switch ($this->semanticsType) {
          case 'NaturalPerson':
            return 'The values in the Subject DN are interpreted according to the rules of a Natural Person';
            break;
          case 'LegalPerson':
            return 'The values in the Subject DN are interpreted according to the rules of a Legal Person';
            break;
          case 'none':
            return 'The values in the Subject DN are open to interpretation as no Semantics Identifier is provided';
            break;
        }
    }
    public function getURI()
    {
        return self::uri;
    }


    public function getBinary()
    {
        return $this->binary;
    }
}
