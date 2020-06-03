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

    public function __construct($id, $parameters = null)
    {
        if (is_array($parameters)) {
            foreach ($parameters as $parameter) {
                $this->parameters[] = $parameter;
            }
        }

        if (is_object($id)) {
            if (get_class($id) == 'eIDASCertificate\AlgorithmIdentifier') {
                $this->algorithmName = $id->getAlgorithmName();
                $this->algorithmOID = $id->getAlgorithmOID();
                $this->parameters = $id->getParameters();
                return;
            }
        } elseif (is_string($id)) {
            if (strpos($id, ".")) {
                $this->algorithmName = OID::getName($id);
                if ($this->algorithmName == 'unknown') {
                    throw new ParseException("Unknown algorithm OID '$id'", 1);
                }
                $this->algorithmOID = OID::getOID($this->algorithmName);
            } else {
                $this->algorithmOID = OID::getOID($id);
                if ($this->algorithmOID == 'unknown') {
                    throw new ParseException("Unknown algorithm name '$id'", 1);
                }
                $this->algorithmName = OID::getName($this->algorithmOID);
            }
        }
    }

    public static function fromDER($der)
    {
        return self::fromSequence(UnspecifiedType::fromDER($der)->asSequence());
    }

    public static function fromSequence($sequence)
    {
        if ($sequence->has(1) && $sequence->at(1)->tag() == 16) {
            $parameters = [];
            foreach ($sequence->at(1)->asSequence()->elements() as $parameter) {
                $parameters[] = $parameter->toDER();
            }
        } else {
            $parameters = null;
        }
        $aid = new AlgorithmIdentifier(
            $sequence->at(0)->asObjectIdentifier()->oid(),
            $parameters
        );
        return $aid;
    }

    public function getASN1()
    {
        $oid = new ObjectIdentifier($this->algorithmOID);
        $seq = new Sequence($oid);
        if (empty($this->parameters)) {
            $seq = $seq->withAppended(new NullType);
        } else {
            $parms = [];
            foreach ($this->parameters as $parameterDER) {
                $parms[] = UnspecifiedType::fromDER($parameterDER)->asTagged();
            }
            $seq = $seq->withAppended(new Sequence(...$parms));
        }
        return $seq;
    }

    public function getBinary($value='')
    {
        return $this->getASN1()->toDER();
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
