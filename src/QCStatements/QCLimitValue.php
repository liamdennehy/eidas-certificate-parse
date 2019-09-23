<?php

namespace eIDASCertificate\QCStatements;

use eIDASCertificate\OID;
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

    public function __construct($qcStatementDER)
    {
        $qcStatement = UnspecifiedType::fromDER($qcStatementDER)->asSequence();
        if ($qcStatement->at(0)->asObjectIdentifier()->oid() != self::oid) {
            throw new QCStatementException("Wrong OID for QC '" . self::type . "'", 1);
        }
        $limitValue = $qcStatement->at(1)->asSequence();

        $this->currency = $limitValue->at(0)->asPrintableString()->string();
        $this->amount = $limitValue->at(1)->asInteger()->intNumber();
        $this->exponent = $limitValue->at(2)->asInteger()->intNumber();
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
}
