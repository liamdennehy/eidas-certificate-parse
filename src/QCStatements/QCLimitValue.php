<?php

namespace eIDASCertificate\QCStatements;

use eIDASCertificate\OID;
use eIDASCertificate\Finding;
use eIDASCertificate\QCStatements\QCStatementException;
use ASN1\Type\UnspecifiedType;

/**
 *
 */
class QCLimitValue extends QCStatement implements QCStatementInterface
{
    const type = 'QcLimitValue';
    const oid = '0.4.0.1862.1.2';

    private $binary;
    private $currency;
    private $amount;
    private $exponent;
    private $findings = [];

    public function __construct($qcStatementDER, $isCritical = false)
    {
        $qcStatement = UnspecifiedType::fromDER($qcStatementDER)->asSequence();
        try {
            $limitValue = $qcStatement->at(1)->asSequence();
            $this->currency = $limitValue->at(0)->asPrintableString()->string();
            $this->amount = $limitValue->at(1)->asInteger()->intNumber();
            $this->exponent = $limitValue->at(2)->asInteger()->intNumber();
        } catch (\Exception $e) {
            $this->findings[] = new Finding(
                self::type,
                'error',
                "Cannot parse QCLimitValue: " .
              base64_encode($qcStatementsDER)
            );
        }

        $this->binary = $qcStatementDER;
    }

    public function getLimit()
    {
        return [
          'currency' => $this->currency,
          'amount' => $this->amount,
          'exponent' => $this->exponent
        ];
    }

    public function getType()
    {
        return self::type;
    }

    public function getDescription()
    {
        $description = "Currency Limit";
        return $description;
    }

    public function getURI()
    {
        return "https://www.etsi.org/deliver/etsi_en/319400_319499/31941205/02.02.01_60/en_31941205v020201p.pdf#chapter-4.3.2";
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
}
