<?php

namespace eIDASCertificate\QCStatements;

use eIDASCertificate\OID;
use eIDASCertificate\Finding;
use eIDASCertificate\Certificate\X509Certificate;
use eIDASCertificate\QCStatements\QCStatementException;
use ASN1\Type\UnspecifiedType;

/**
 *
 */
class QCType extends QCStatement implements QCStatementInterface
{
    private $qcType;
    private $findings = [];

    const type = 'QCQualifiedType';
    const oid = '0.4.0.1862.1.6';

    public function __construct($qcStatementDER, $isCritical = false)
    {
        $qcStatement = UnspecifiedType::fromDER($qcStatementDER)->asSequence();
        switch (true) {
          case $qcStatement->count() > 2:
            $this->findings[] = new Finding(
                self::type,
                'error',
                "More than one entry in QCType Statement: ".base64_encode($qcStatementDER)
            );
            break;

          case $qcStatement->count() < 2:
            $this->findings[] = new Finding(
                self::type,
                'error',
                "No entries in QCType Statement: ".base64_encode($qcStatementDER)
            );
            break;
          default:
            $qcTypes = $qcStatement->at(1)->asSequence();
            if ($qcTypes->count() > 1) {
                $this->findings[] = new Finding(
                    self::type,
                    'error',
                    "Multiple QCType statements not permitted: ".base64_encode($qcStatementDER)
                );
            } else {
                $qcTypeOID = $qcTypes->at(0)->asObjectIdentifier()->oid();
                $qcTypeName = OID::getName($qcTypeOID);
                switch ($qcTypeName) {
                case 'esign':
                case 'eseal':
                case 'web':
                  $this->qcType = $qcTypeName;
                  break;

                default:
                  $this->findings[] = new Finding(
                      self::type,
                      'error',
                      "Unrecognised QCType OID $qcTypeOID ($qcTypeName): ".base64_encode($qcStatementDER)
                  );
                  break;
              }
            }
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
            return "QCType malformed or not recognised";
            break;
        }
    }

    public function getURI()
    {
        return "https://www.etsi.org/deliver/etsi_en/319400_319499/31941205/02.02.01_60/en_31941205v020201p.pdf#chapter-4.2.3";
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
        null;
    }

    public function getAttributes()
    {
        return [];
    }
}
