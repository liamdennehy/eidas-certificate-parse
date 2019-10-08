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
class QCRetentionPeriod extends QCStatement implements QCStatementInterface
{
    private $retentionPeriod;
    private $findings = [];
    private $binary;

    const oid = '0.4.0.1862.1.3';
    const type = 'QCRetentionPeriod';

    public function __construct($qcStatementDER, $isCritical = false)
    {
        try {
            $statement = UnspecifiedType::fromDER($qcStatementDER)->asSequence();
            $this->retentionPeriod = $statement->at(1)->asInteger()->intNumber();
        } catch (\Exception $e) {
            $this->findings[] = new Finding(
                self::type,
                'error',
                "Cannot understand QCRetentionPeriod: " .
              base64_encode($qcStatementsDER)
            );
        }

        $this->binary = $qcStatementDER;
    }

    public function getRetentionPeriodYears()
    {
        return $this->retentionPeriod;
    }

    public function getType()
    {
        return self::type;
    }

    public function getDescription()
    {
        return "Information about the subject of this certificate will be ".
        "retained by the CA for " . $this->retentionPeriod . " years after ".
        "the certificate expiry date";
    }

    public function getURI()
    {
        return "https://www.etsi.org/deliver/etsi_en/319400_319499/31941205/02.02.01_60/en_31941205v020201p.pdf#chapter-4.3.3";
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
