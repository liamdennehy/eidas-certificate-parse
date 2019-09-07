<?php

namespace eIDASCertificate\QCStatements;

use FG\ASN1\ASNObject;
use eIDASCertificate\OID;

/**
 *
 */
class QCSyntaxV2 extends QCStatement implements QCStatementInterface
{
    private $oid;
    private $semanticsType;

    public function __construct($statement)
    {
        $this->oid = $statement[0];
        array_shift($statement);
        if (sizeof($statement) > 1) {
            throw new QCStatementException("More than one entry in QCSyntaxV2 Statement", 1);
        };
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
        // throw new QCStatementException("QCSyntaxV2 not yet implemented");
    }

    public function getType()
    {
        return 'QCSyntaxV2-' . $this->semanticsType;
    }
}
