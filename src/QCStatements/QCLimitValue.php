<?php

namespace eIDASCertificate\QCStatements;

use FG\ASN1\ASNObject;
use FG\ASN1\Identifier;
use FG\ASN1\TemplateParser;
use eIDASCertificate\OID;
use eIDASCertificate\QCStatements\QCStatementException;

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

    public function __construct($statements)
    {
      $qcLimitValueTemplate = [
        Identifier::SEQUENCE => [
          Identifier::OBJECT_IDENTIFIER,
          Identifier::SEQUENCE => [
            Identifier::PRINTABLE_STRING,
            Identifier::INTEGER,
            Identifier::INTEGER
          ]
        ]
      ];
      $parser = new TemplateParser();
      try {
        $statement = $parser->parseBinary($statements, $qcLimitValueTemplate);
      } catch (\Exception $e) {
        // var_dump(new ASNObject($statements));
        throw new QCStatementException("Error Parsing QCLimitvalue Statement", 1);
      }

      if ($statement[0]->getContent() <> self::oid) {
            throw new QCStatementException("Wrong OID for QC '" . self::type . "'", 1);
      }

      $this->currency = $statement[1][0]->getContent();
      $this->amount = $statement[1][1]->getContent();
      $this->exponent = $statement[1][2]->getContent();
      var_dump([
        $this->currency,
        $this->amount,
        $this->exponent
      ]);

        $this->binary = $statements;
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
