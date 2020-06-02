<?php

namespace eIDASCertificate\OCSP;

use ASN1\Type\UnspecifiedType;
use ASN1\Type\Constructed\Sequence;
use ASN1\Type\Primitive\OctetString;
use ASN1\Type\Primitive\Integer;
use eIDASCertificate\ASN1Interface;
use eIDASCertificate\AlgorithmIdentifier;
use eIDASCertificate\AttributeInterface;

class CertID implements ASN1Interface, AttributeInterface
{
    private $binary;
    private $algorithmIdentifier;
    private $issuerNameHash;
    private $issuerKeyHash;
    private $serialNumber;

    public function __construct(
        $signatureAlgorithm,
        $issuerNameHash,
        $issuerKeyHash,
        $serialNumber
    ) {
        if (! is_a($signatureAlgorithm, 'eIDASCertificate\AlgorithmIdentifier')) {
            $this->algorithmIdentifier = new AlgorithmIdentifier($signatureAlgorithm);
        } else {
            $this->algorithmIdentifier = $signatureAlgorithm;
        }
        $this->issuerNameHash = $issuerNameHash;
        $this->issuerKeyHash = $issuerKeyHash;
        $this->serialNumber = hex2bin($serialNumber);
    }

    public static function fromDER($der)
    {
        return self::fromSequence(UnspecifiedType::fromDER($der)->asSequence());
    }

    public static function fromSequence($obj)
    {
        $signatureAlgorithm = AlgorithmIdentifier::fromSequence($obj->at(0)->asSequence());
        $issuerNameHash = $obj->at(1)->asOctetString()->string();
        $issuerKeyHash = $obj->at(2)->asOctetString()->string();
        $serialNumber = gmp_strval($obj->at(3)->asInteger()->number(), 16);
        return new CertID($signatureAlgorithm, $issuerNameHash, $issuerKeyHash, $serialNumber);
    }

    public function getASN1()
    {
        return (
          new Sequence(
              $this->algorithmIdentifier->getASN1(),
              new OctetString($this->issuerNameHash),
              new OctetString($this->issuerKeyHash),
              new Integer(
                  gmp_strval(
                      gmp_init($this->getSerialNumber(), 16),
                      10
                  )
              )
          )
        );
    }

    public function getBinary()
    {
        return $this->getASN1()->toDER();
    }

    public function getHashAlgorithm()
    {
        return $this->algorithmIdentifier;
    }

    public function getAlgorithmName()
    {
        return $this->algorithmIdentifier->getAlgorithmName();
    }

    public function getAlgorithmOID()
    {
        return $this->algorithmIdentifier->getAlgorithmOID();
    }

    public function getIssuerNameHash()
    {
        return $this->issuerNameHash;
    }

    public function getIssuerKeyHash()
    {
        return $this->issuerKeyHash;
    }

    public function getSerialNumber()
    {
        return bin2hex($this->serialNumber);
    }

    public function getAttributes()
    {
        $attr = [
          'serialNumber' => $this->getSerialNumber(),
          'algorithmName' => $this->getAlgorithmName(),
          'issuerKeyHash' => bin2hex($this->getIssuerKeyHash()),
          'issuerNameHash' => bin2hex($this->getIssuerNameHash())
        ];
        return $attr;
    }
}
