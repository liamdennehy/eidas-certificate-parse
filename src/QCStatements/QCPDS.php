<?php

namespace eIDASCertificate\QCStatements;

use eIDASCertificate\OID;
use eIDASCertificate\QCStatements\QCStatementException;
use ASN1\Type\UnspecifiedType;

/**
 *
 */
class QCPDS extends QCStatement implements QCStatementInterface
{
    private $pdsLocations;
    private $binary;

    const type = 'QCPDS';
    const oid = '0.4.0.1862.1.5';

    public function __construct($qcStatementDER)
    {
        $qcStatement = UnspecifiedType::fromDER($qcStatementDER)->asSequence();
        if ($qcStatement->at(0)->asObjectIdentifier()->oid() != self::oid) {
            throw new QCStatementException("Wrong OID for QC '" . self::type . "'", 1);
        }
        if ($qcStatement->count() > 2) {
            throw new QCStatementException("More than one entry in PDS Statement", 1);
        } elseif ($qcStatement->count() <2) {
            throw new QCStatementException("No entries in PDS Statement", 1);
        };
        try {
            $pdsLocations = $qcStatement->at(1)->asSequence()->elements();
            foreach ($qcStatement->at(1)->asSequence()->elements() as $pdsLocation) {
                $pdsLocation = $pdsLocation->asSequence();
                $location['url'] = $pdsLocation->at(0)->asIA5String()->string();
                $location['language'] = strtolower($pdsLocation->at(1)->asPrintableString()->string());
                $this->pdsLocations[] = $location;
            }
        } catch (\Exception $e) {
            // TODO: Figure out strange PDS
          // throw new \Exception("Cannot understand PDS: ". base64_encode($qcStatementDER), 1);
        }

        $this->binary = $qcStatementDER;
    }

    public function getLocations()
    {
        return $this->pdsLocations;
    }

    public function getType()
    {
        return self::type;
    }

    public function getDescription()
    {
        if (sizeof($this->pdsLocations) == 0) {
            $description = "This QCStatement should hold URLs to PKI Disclosure ".
            "Statements, but none are present";
        } else {
            $description = sizeof($this->pdsLocations)." PKI Disclosure Statement";
            if (sizeof($this->pdsLocations) > 1) {
                $description .= "s";
            }
            $description .= " (PDS) are available: ";
            $locations = [];
            foreach ($this->pdsLocations as $pdsLocation) {
                $locations[] = "(" . $pdsLocation['language'] . ") " . $pdsLocation['url'];
            }
            $description .= implode(", ", $locations);
        }

        return $description;
        // s (PDS)";
    }

    public function getURI()
    {
        return "https://www.etsi.org/deliver/etsi_en/319400_319499/31941205/02.02.01_60/en_31941205v020201p.pdf#chapter-4.3.4";
    }

    public function getBinary()
    {
        return $this->binary;
    }
}
