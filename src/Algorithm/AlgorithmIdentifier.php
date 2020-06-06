<?php

namespace eIDASCertificate\Algorithm;

use eIDASCertificate\ASN1Interface;
use eIDASCertificate\Algorithm;
use eIDASCertificate\OID;
use eIDASCertificate\ParseException;
use eIDASCertificate\Algorithm\RSAAlgorithm;
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
            if (get_class($id) == 'eIDASCertificate\Algorithm\AlgorithmIdentifier') {
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
        } else {
          throw new \Exception("Cannot recognise input to AlgorithIdentifier", 1);

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

    public function getCipherName()
    {
        switch ($this->algorithmName) {
          case 'sha512WithRSAEncryption':
          case 'sha384WithRSAEncryption':
          case 'sha256WithRSAEncryption':
          case 'sha1WithRSAEncryption':
            // code...
            break;
          default:
            throw new \Exception("'".$this->algorithmName."' is not a recognised cipher algorithm", 1);

            break;
        }
    }

    public function getDigestName()
    {
        switch ($this->algorithmName) {
          case 'sha512WithRSAEncryption':
            return 'sha-512';
            break;
          case 'sha384WithRSAEncryption':
            return 'sha-384';
            break;
          case 'sha256WithRSAEncryption':
            return 'sha-256';
            break;
          case 'sha1WithRSAEncryption':
            return 'sha-1';
            break;
          default:
            throw new \Exception("'".$this->algorithmName."' does not have a recognised digest algorithm", 1);

            break;
        }
    }

    public function getAlgorithm()
    {
        switch ($this->getAlgorithmName()) {
          case 'sha512WithRSAEncryption':
          case 'sha384WithRSAEncryption':
          case 'sha256WithRSAEncryption':
          case 'sha1WithRSAEncryption':
            return new RSAAlgorithm(clone $this);
            break;

          default:
            throw new \Exception("Unknown algorithm ".$this->algorithmName, 1);

            break;
        }
    }
}
