<?php

namespace eIDASCertificate\OCSP;

use ASN1\Type\UnspecifiedType;
use ASN1\Type\Constructed\Sequence;
use ASN1\Type\Primitive\OctetString;
use ASN1\Type\Primitive\Integer;
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
        // var_dump($obj);
        $signatureAlgorithm = AlgorithmIdentifier::fromDER($obj->at(0)->toDER());
        $issuerNameHash = $obj->at(1)->asOctetString()->string();
        $issuerKeyHash = $obj->at(2)->asOctetString()->string();
        $serialNumber = $obj->at(3)->asInteger()->number();
        return new CertID($signatureAlgorithm, $issuerNameHash, $issuerKeyHash, $serialNumber);
    }

    public function getASN1()
    {
        return (new Sequence(
            $this->algorithmIdentifier->getASN1(),
            new OctetString($this->issuerNameHash),
            new OctetString($this->issuerKeyHash),
            new Integer($this->serialNumber),
        ));
    }

    public function getBinary()
    {
        return $this->getASN1()->toDER();
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
