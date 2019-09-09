<?php

namespace eIDASCertificate\QCStatements;

use FG\ASN1\ASNObject;
use eIDASCertificate\OID;

/**
 *
 */
class QCSyntaxV2 extends QCStatement implements QCStatementInterface
{
    const type = 'QCSyntaxV2';

    const oid = '1.3.6.1.5.5.7.11.2';
    private $semanticsType;

    public function __construct($statements)
    {
        $statement = $statements->getContent();

        if ($statement[0]->getContent() != self::oid) {
            throw new QCStatementException("Wrong OID for QC '" . self::type . "'", 1);
        }
        array_shift($statement);
        if (sizeof($statement) > 1) {
            throw new QCStatementException("More than one entry in QCSyntaxV2 Statement", 1);
        } elseif (sizeof($statement) == 0) {
            // TODO: What fresh hell is this?
            $this->semanticsType = 'none';

        } else {
            $semanticsType = $statement[0][0]->getContent();
            switch ($semanticsType) {
              case '0.4.0.194121.1.2':
              $this->semanticsType = 'LegalPerson';
              break;
              case '0.4.0.194121.1.1':
              $this->semanticsType = 'NaturalPerson';
              break;

              default:
              throw new QCStatementException("QCSyntaxV2 statement '".$statement[0][0]->getContent()."' not yet implemented");
              break;
            }
        }
        $this->binary = $statements->getBinary();
    }

    public function getType()
    {
        return self::type .'-' . $this->semanticsType;
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
          case null:
            return 'The values in the Subject DN are open to interpretation as no Semantics Identifier is provided';
            break;
        }
    }
    public function getURI()
    {
        return 'https://www.etsi.org/deliver/etsi_en/319400_319499/31941201/01.01.01_60/en_31941201v010101p.pdf#chapter-5.1';
    }


    public function getBinary()
    {
        return $this->binary;
    }
}
