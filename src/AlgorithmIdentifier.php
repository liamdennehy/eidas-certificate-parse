<?php

namespace eIDASCertificate;

use eIDASCertificate\OID;
use eIDASCertificate\ParseException;
use ASN1\Type\UnspecifiedType;

class AlgorithmIdentifier implements ASN1Interface
{
    private $binary;
    private $algorithmName;
    private $algorithmOID;
    private $parameters;

    public function __construct($id, $parameters = null)
    {
        if (! is_null($parameters)) {
            throw new ParseException("Cannot handle Algorithm Parameters", 1);
        }
        if (strpos($id, ".")) {
            $this->algorithmName = OID::getName($id);
            if ($this->algorithmName == 'unknown') {
                throw new ParseException("Unknown algorithm OID '$id'", 1);
            }
            $this->algorithmOID = $id;
        } else {
            $this->algorithmOID = OID::getOID($id);
            if ($this->algorithmOID == 'unknown') {
                throw new ParseException("Unknown algorithm name '$id'", 1);
            }
            $this->algorithmName = $id;
        }
    }
    public static function fromDER($der)
    {
        $obj = UnspecifiedType::fromDER($der)->asSequence();
        $parameters = null;
        if ($obj->has(1)) {
            if ($obj->at(1)->typeClass() !== 0) {
                throw new ParseException("Cannot handle Algorithm Parameters '".base64_encode($der)."'", 1);
            };
        }
        $aid = new AlgorithmIdentifier(
            $obj->at(0)->asObjectIdentifier()->oid(),
            $parameters
        );
        return $aid;
    }

    public function getBinary()
    {
        return $this->binary;
    }

    public function getAlgorithmName()
    {
        return $this->algorithmName;
    }

    public function getAlgorithmOID()
    {
        return $this->algorithmOID;
    }
}
