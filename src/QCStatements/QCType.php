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
    private $qcPurpose;
    private $findings = [];

    const type = 'QCQualifiedType';
    const oid = '0.4.0.1862.1.6';
    const uri = 'https://www.etsi.org/deliver/etsi_en/319400_319499/31941205/02.02.01_60/en_31941205v020201p.pdf#chapter-4.2.3';
    const qSigCDescription =
      'Certificate for Electronic Signatures (QSigC) according to '.
      'Regulation (EU) No 910/2014 Article 28';
    const qSealCDescription =
      'Certificate for Electronic Signatures (QSealC) according to '.
      'Regulation (EU) No 910/2014 Article 38';
    const qWACDescription =
      'Certificate for Electronic Signatures (QWAC) according to '.
      'Regulation (EU) No 910/2014 Article 45';


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
                  $this->qcType = 'QSigC';
                  $this->description = self::qSigCDescription;
                  break;
                case 'eseal':
                  $this->qcType = 'QSealC';
                  $this->description = self::qSealCDescription;
                  break;
                case 'web':
                  $this->qcType = 'QWAC';
                  $this->description = self::qWACDescription;
                  break;

                default:
                  $this->findings[] = new Finding(
                      self::type,
                      'error',
                      "Unrecognised QCType OID $qcTypeOID ($qcTypeName): ".base64_encode($qcStatementDER)
                  );
                  break;
              }
                $this->qcPurpose = $qcTypeName;
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

    public function getQCPurpose()
    {
        return $this->qcPurpose;
    }

    public function getDescription()
    {
        return $this->description;
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
        null;
    }

    public function getAttributes()
    {
        // TODO: QCType Sanity checks?
        return
        [
          'qualification' => [
            'type' => $this->qcType,
            'purpose' => $this->getDescription()
          ],
          'keyPurposes' => [
            'qualified' => $this->qcPurpose
          ]
        ];
    }
}
