<?php

namespace eIDASCertificate\QCStatements;

use eIDASCertificate\OID;
use eIDASCertificate\Finding;
use eIDASCertificate\Certificate\X509Certificate;
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
    private $subjectDN;
    private $findings = [];

    public function __construct($qcStatementDER, $isCritical = false)
    {
        $qcStatement = UnspecifiedType::fromDER($qcStatementDER)->asSequence();
        if ($qcStatement->count() < 2) {
            $this->semanticsType = 'notProvided';
            $this->findings[] = new Finding(
                self::type,
                'error',
                "No QCSyntaxV2 Statements found: ".base64_encode($qcStatementDER)
            );
        // throw new QCStatementException("No QCSyntaxV2 Statements found: ".base64_encode($qcStatementDER), 1);
        } elseif ($qcStatement->count() > 2) {
            $this->findings[] = new Finding(
                self::type,
                'error',
                "More than one entry in QCSyntaxV2 Statement: ".base64_encode($qcStatementDER)
            );
        // throw new QCStatementException("More than one entry in QCSyntaxV2 Statement", 1);
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
                $this->findings[] = new Finding(
                    self::type,
                    'error',
                    "QCSyntaxV2 semantics type '$semanticsType' not understood: ".base64_encode($qcStatementDER)
                );
                // throw new QCStatementException("QCSyntaxV2 statement '$semanticsType' not yet implemented");
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

    public function getFindings()
    {
        return $this->findings;
    }

    public function getIsCritical()
    {
        return false;
    }

    public function setCertificate(X509Certificate $cert)
    {
        $this->subject = $cert->getSubjectExpanded();
    }

    public function getAttributes()
    {
        return [
          'subject' => [
            'syntax' => $this->getDescription()
            ]
          ];
    }
}
