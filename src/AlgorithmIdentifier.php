<?php

namespace eIDASCertificate;

use eIDASCertificate\OID;
use eIDASCertificate\ParseException;
use ASN1\Type\UnspecifiedType;
use ASN1\Type\Constructed\Sequence;
use ASN1\Type\Primitive\ObjectIdentifier;
use ASN1\Type\Primitive\NullType;

class AlgorithmIdentifier implements ASN1Interface
{
    private $binary;
    private $algorithmName;
    private $algorithmOID;
    private $parametersIncluded;
    private $parameters = [];

    public function __construct($id, $parameters = null, $parametersIncluded = true)
    {
        if (is_array($parameters)) {
            foreach ($parameters as $parameter) {
                $this->parameters[] = $parameter;
            }
        }
        $this->parametersIncluded = $parametersIncluded;
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
        if ($obj->has(1) && $obj->at(1)->tag() == 16) {
            $parameters = [];
            foreach ($obj->at(1)->asSequence()->elements() as $parameter) {
                $parameters[] = $parameter->toDER();
            }
        } else {
            $parameters = null;
        }
        $aid = new AlgorithmIdentifier(
            $obj->at(0)->asObjectIdentifier()->oid(),
            $parameters
        );
        return $aid;
    }

    public function getBinary()
    {
        $oid = new ObjectIdentifier($this->algorithmOID);
        if (empty($this->parameters && $this->parametersIncluded)) {
            if ($this->parametersIncluded) {
                return (new Sequence($oid, new NullType))->toDER();
            } else {
                return (new Sequence($oid))->toDER();
            }
        } else {
            foreach ($this->parameters as $parameterDER) {
                $parameters[] = UnspecifiedType::fromDER($parameterDER)->asTagged();
            }
            return (new Sequence($oid, new Sequence(...$parameters)))->toDER();
        }
    }

    public function getAlgorithmName()
    {
        return $this->algorithmName;
    }

    public function getAlgorithmOID()
    {
        return $this->algorithmOID;
    }

    public function getParameters()
    {
        $parameters = [];
        foreach ($this->parameters as $parameter) {
            $parameters[] = base64_encode($parameter);
        }
        return $parameters;
    }
}