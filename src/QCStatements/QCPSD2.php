<?php

namespace eIDASCertificate\QCStatements;

use FG\ASN1\ASNObject;
use eIDASCertificate\OID;
use eIDASCertificate\QCStatements\QCStatementException;

/**
 *
 */
class QCPSD2 extends QCStatement implements QCStatementInterface
{
    private $psd2Roles = [];
    private $psd2NCALongName;
    private $psd2NCAShortName;
    const type = 'QCPSD2';
    const oid = '0.4.0.19495.2';

    public function __construct($statements)
    {
        $statement = $statements->getContent();
        if ($statement[0]->getContent() != self::oid) {
            throw new QCStatementException("Wrong OID for QCStatement '" . self::type . "'", 1);
        }
        array_shift($statement);
        if (sizeof($statement) > 1) {
            throw new QCStatementException("More than one entry in PSD2 Statement", 1);
        } elseif (sizeof($statement) == 0) {
            throw new QCStatementException("No entries in PSD2 Statement", 1);
        };
        $psd2Statement = $statement[0];
        if (sizeof($psd2Statement) != 3) {
            throw new QCStatementException("PSD2 Statement has wrong number of elements", 1);
        };
        $rolesStatement = $psd2Statement[0];
        foreach ($rolesStatement as $role) {
            if (get_class($role) != "FG\ASN1\Universal\Sequence") {
                throw new QCStatementException(
                    "PSD2 Roles not encoded as a Sequence: '" .
                    base64_encode($statements->getBinary()).
                    "'",
                    1
                );
            }
            $psd2Role = OID::getName($role[0]->getContent());
            if ($psd2Role == 'unkown') {
                throw new QCStatementException("Unknown PSD2 Role '$psd2Role'", 1);
            }
            switch ($psd2Role) {
              case 'PSP_AS':
              case 'PSP_PI':
              case 'PSP_AI':
              case 'PSP_IC':
                if ($psd2Role != $role[1]->getContent()) {
                    throw new QCStatementException(
                        "PSD2 Named Role '".
                            $role[1]->getContent().
                            "' does not match OID Name '$psd2Role': '" .
                            base64_encode($psd2Statement->getBinary()) .
                        "'",
                        1
                    );
                }
                $this->psd2Roles[] = $psd2Role;
                break;

              default:
                throw new QCStatementException(
                    "PSD2 Named Role '".$role[1]->getContent()."' unknown",
                    1
                );
                break;
            }
        }
        if ($psd2Statement[1]->getType() != 12) {
            throw new QCStatementException(
                "PSD2 NCA Long Name not in string format",
                1
            );
        } else {
            $this->psd2NCALongName = $psd2Statement[1]->getContent();
        }
        if ($psd2Statement[2]->getType() != 12) {
            throw new QCStatementException(
                "PSD2 NCA Short Name not in string format",
                1
            );
        } else {
            $this->psd2NCAShortName = $psd2Statement[2]->getContent();
        }
        $this->binary = $statements->getBinary();
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
        return "https://www.etsi.org/deliver/etsi_ts/119400_119499/119495/01.03.02_60/ts_119495v010302p.pdf#chapter-5.1";
    }

    public function getBinary()
    {
        return $this->binary;
    }
}
