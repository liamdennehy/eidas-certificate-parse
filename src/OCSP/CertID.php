<?php

namespace eIDASCertificate\OCSP;

use ASN1\Type\UnspecifiedType;
use eIDASCertificate\ASN1Interface;

class CertID implements ASN1Interface
{
    private $binary;
    private $hashAlgorithm;
    private $issuerNameHash;
    private $issuerKeyHash;
    private $serialNumber;

    public function __construct(
      $hashAlgorithm,
      $issuerNameHash,
      $issuerKeyHash,
      $serialNumber)
    {
      $this->binary = (new Sequence())->toDER();
    }
    public static function fromDER($der)
    {
        $request = UnspecifiedType::fromDER($der)->asSequence();
        $this->binary = $der;
    }

    public function getBinary()
    {
        return $this->binary;
    }
}
