<?php

namespace eIDASCertificate\QCStatements;

use FG\ASN1\ASNObject;
use FG\ASN1\Identifier;
use FG\ASN1\TemplateParser;
use eIDASCertificate\OID;

/**
 *
 */
class QCCompliance extends QCStatement implements QCStatementInterface
{
    private $binary;
    const type = 'QCCompliance';
    const oid = '0.4.0.1862.1.1';

    public function __construct($statements)
    {
        $qcComplianceStatementTemplate = [
          Identifier::SEQUENCE => [
            Identifier::OBJECT_IDENTIFIER
          ]
        ];
        $parser = new TemplateParser();
        try {
            $statement = $parser->parseBinary($statements, $qcComplianceStatementTemplate);
        } catch (\Exception $e) {
            throw new QCStatementException("Error Parsing QCComplianceStatement Statement", 1);
        }

        if ($statement[0]->getContent() != self::oid) {
            throw new QCStatementException("Wrong OID for QC '" . self::type . "'", 1);
        }
        $this->binary = $statements;
    }

    public function getType()
    {
        return self::type;
    }

    public function getDescription()
    {
        return "The certificate is an EU ".
        "qualified certificate that is issued according to Directive ".
        "1999/93/EC or the Annex I, III or IV of the Regulation ".
        "(EU) No 910/2014 whichever is in force at the time of issuance.";
    }

    public function getURI()
    {
        return "https://www.etsi.org/deliver/etsi_en/319400_319499/31941205/02.02.01_60/en_31941205v020201p.pdf#chapter-4.2.1";
    }

    public function getBinary()
    {
        return $this->binary;
    }
}
