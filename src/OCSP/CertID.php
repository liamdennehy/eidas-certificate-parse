<?php

namespace eIDASCertificate\OCSP;

use ASN1\Type\UnspecifiedType;
use ASN1\Type\Constructed\Sequence;
use ASN1\Type\Primitive\OctetString;
use ASN1\Type\Primitive\Integer;
use eIDASCertificate\ASN1Interface;
use eIDASCertificate\Algorithm\AlgorithmIdentifier;
use eIDASCertificate\AttributeInterface;

class CertID implements ASN1Interface, AttributeInterface
{
    private $binary;
    private $algorithmIdentifier;
    private $issuerNameHash;
    private $issuerKeyHash;
    private $serialNumber; // as lowercase hex string
    private $signer; // The eventual signer of the reponse this object is contained in.

    public function __construct(
        $hashAlgorithm,
        $issuerNameHash,
        $issuerKeyHash,
        $serialNumber
    ) {
        if (is_a($hashAlgorithm, 'eIDASCertificate\AlgorithmIdentifier')) {
            $this->hashAlgorithm = $hashAlgorithm;
        } else {
            $this->hashAlgorithm = new AlgorithmIdentifier($hashAlgorithm);
        }
        $this->issuerNameHash = $issuerNameHash;
        $this->issuerKeyHash = $issuerKeyHash;
        $this->serialNumber = strtolower($serialNumber);
    }

    public static function fromDER($der)
    {
        return self::fromSequence(UnspecifiedType::fromDER($der)->asSequence());
    }

    public static function fromSequence($obj)
    {
        $hashAlgorithm = AlgorithmIdentifier::fromSequence($obj->at(0)->asSequence());
        $issuerNameHash = $obj->at(1)->asOctetString()->string();
        $issuerKeyHash = $obj->at(2)->asOctetString()->string();
        $serialNumber = gmp_strval($obj->at(3)->asInteger()->number(), 16);
        return new CertID($hashAlgorithm, $issuerNameHash, $issuerKeyHash, $serialNumber);
    }

    public function getASN1()
    {
        return (
          new Sequence(
              $this->hashAlgorithm->getASN1(),
              new OctetString($this->issuerNameHash),
              new OctetString($this->issuerKeyHash),
              new Integer(
                  gmp_strval(
                      '0x'.$this->serialNumber,
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
        return $this->hashAlgorithm;
    }

    public function getAlgorithmName()
    {
        return $this->hashAlgorithm->getAlgorithmName();
    }

    public function getAlgorithmOID()
    {
        return $this->hashAlgorithm->getAlgorithmOID();
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

    public function getAttributes()
    {
        $algo = $this->getAlgorithmName();
        $issuerKeyHash = $this->getIssuerKeyHash($algo);
        $issuerNameHash = $this->getIssuerNameHash($algo);
        $attr = [
          'serialNumber' => $this->getSerialNumber(),
          'algorithmName' => $this->getAlgorithmName(),
          'issuerKeyHash' => bin2hex($issuerKeyHash),
          'issuerNameHash' => bin2hex($issuerNameHash)
        ];
        if (! empty($this->signer)) {
            $signerKeyHash = $this->signer->getSubjectPublicKeyHash($algo);
            $signerNaneHash = $this->signer->getSubjectNameHash($algo);
            if ($issuerKeyHash == $signerKeyHash && $issuerNameHash == $signerNaneHash) {
                $attr['signerIsIssuer'] = true;
            } else {
                $attr['signerIsIssuer'] = false;
            }
            // TODO: Check OCSP Signer has ocspsigning EKU or or issuer
        } else {
            $attr['signerIsIssuer'] = 'unknown';
        }
        return $attr;
    }

    public function setSigner($signer)
    {
        $this->signer = $signer;
    }

    public function getIdentifier()
    {
        return hash(
            'sha256',
            $this->issuerNameHash.
            $this->issuerKeyHash.
            $this->serialNumber,
            true
        );
    }
}
