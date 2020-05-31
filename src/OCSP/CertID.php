<?php

namespace eIDASCertificate\OCSP;

use ASN1\Type\UnspecifiedType;
use eIDASCertificate\ASN1Interface;
use eIDASCertificate\AlgorithmIdentifier;

class CertID implements ASN1Interface
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
        $this->serialNumber = $serialNumber;
    }

    public static function fromDER($der)
    {
        $obj = UnspecifiedType::fromDER($der)->asSequence();
        $signatureAlgorithm = AlgorithmIdentifier::fromDER($obj->at(0)->toDER());
        $issuerNameHash = $obj->at(1)->asString()->string();
        $issuerKeyHash = $obj->at(2)->asString()->string();
        $serialNumber = $obj->at(3)->asInteger()->number();
        return new CertID($signatureAlgorithm, $issuerNameHash, $issuerKeyHash, $serialNumber);
    }

    public function getBinary()
    {
        return $this->binary;
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
        return $this->serialNumber;
    }
}
