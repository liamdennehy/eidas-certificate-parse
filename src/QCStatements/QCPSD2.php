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
class QCPSD2 extends QCStatement implements QCStatementInterface
{
    private $psd2Roles = [];
    private $psd2NCALongName;
    private $psd2NCAShortName;
    private $findings = [];

    const type = 'QCPSD2';
    const oid = '0.4.0.19495.2';
    const uri = 'https://www.etsi.org/deliver/etsi_ts/119400_119499/119495/01.03.02_60/ts_119495v010302p.pdf#chapter-5.1';

    public function __construct($qcStatementDER, $isCritical = false)
    {
        $qcStatement = UnspecifiedType::fromDER($qcStatementDER)->asSequence();
        if ($qcStatement->count() > 2) {
            $this->findings[] = new Finding(
                self::type,
                'error',
                "More than one entry in PSD2 Statement: " .
                base64_encode($qcStatementsDER)
            );
        } elseif ($qcStatement->count() < 2) {
            $this->findings[] = new Finding(
                self::type,
                'error',
                "No entries in PSD2 Statement: " .
                base64_encode($qcStatementsDER)
            );
        } else {
            try {
                $psd2Authorisation = $qcStatement->at(1)->asSequence();
                $psd2Roles = $psd2Authorisation->at(0)->asSequence();
                foreach ($psd2Roles->elements() as $psd2Role) {
                    $psd2Role = $psd2Role->asSequence();
                    $psd2RoleOID = $psd2Role->at(0)->asObjectIdentifier()->oid();
                    $psd2RoleName = OID::getName($psd2RoleOID);
                    if ($psd2RoleName == 'unkown') {
                        $this->findings[] = new Finding(
                            self::type,
                            'error',
                            "Unrecognised PSD2 Role '$psd2Role': ".
                    base64_encode($qcStatementDER)
                        );
                    }
                    $psd2RoleProvidedName = $psd2Role->at(1)->asUTF8String()->string();
                    if ($psd2RoleProvidedName != $psd2RoleName) {
                        $this->findings[] = new Finding(
                            self::type,
                            'error',
                            "Included PSD2 Named Role '$psd2RoleProvidedName' ".
                    "does not match OID Name '$psd2RoleName': ".
                    base64_encode($qcStatementDER)
                        );
                    }
                    switch ($psd2RoleName) {
                  case 'PSP_AS':
                  case 'PSP_PI':
                  case 'PSP_AI':
                  case 'PSP_IC':
                    $this->psd2Roles[] = $psd2RoleName;
                    break;

                  default:
                    $this->findings[] = new Finding(
                        self::type,
                        'error',
                        "PSD2 Role OID $psd2RoleOID ($psd2RoleName) not recognised: " .
                      base64_encode($qcStatementDER)
                    );
                    break;
                }
                }
                $this->psd2NCALongName = $psd2Authorisation->at(1)->asUTF8String()->string();
                $this->psd2NCAShortName = $psd2Authorisation->at(2)->asUTF8String()->string();
            } catch (\Exception $e) {
                $this->findings[] = new Finding(
                    self::type,
                    'error',
                    "Malformed PSD2 Statement, ".
                $e->getMessage().": ".
                base64_encode($qcStatementDER)
                );
            }
        }
        $this->binary = $qcStatementDER;
    }

    public function getType()
    {
        return self::type;
    }

    public function getRoles()
    {
        return $this->psd2Roles;
    }

    public function getAuthorisations()
    {
        return [
          'roles' => $this->psd2Roles,
          'NCAShortName' => $this->psd2NCAShortName,
          'NCALongName' => $this->psd2NCALongName
        ];
    }


    public function getDescription()
    {
        $description = "'".$this->psd2NCALongName.
          "' has authorised the subject of this certificate to operate ".
          "with the following PSD2 Roles: ".implode(", ", $this->psd2Roles);
        return $description;
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
        return ['PSD2' => $this->getAuthorisations()];
    }
}
