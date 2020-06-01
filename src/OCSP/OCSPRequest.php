<?php

namespace eIDASCertificate\OCSP;

use ASN1\Type\UnspecifiedType;
use ASN1\Type\Constructed\Sequence;
use eIDASCertificate\Extensions;
use eIDASCertificate\Certificate\X509Certificate;
use eIDASCertificate\OCSP\TBSRequest;
use eIDASCertificate\AttributeInterface;
use eIDASCertificate\ParseInterface;
use eIDASCertificate\ASN1Interface;
use eIDASCertificate\ParseException;
use eIDASCertificate\AlgorithmIdentifier;

class OCSPRequest implements
    AttributeInterface,
    ParseInterface,
    ASN1Interface
{
    private $attributes = [];
    private $version;
    private $binary;
    private $tbsRequest;
    private $nonce;

    public function __construct(
        $signatureAlgorithm,
        $issuerNameHash,
        $issuerKeyHash,
        $serialNumber,
        $nonce = 'none'
    ) {
        if ($nonce == 'auto') {
            $this->nonce = random_bytes(16);
        } elseif ($nonce == 'none') {
            $this->nonce == null;
        } else {
            $this->nonce = $nonce;
        }

        if (is_string($signatureAlgorithm)) {
            $signatureAlgorithm = new AlgorithmIdentifier($signatureAlgorithm);
        }
        if (get_class($signatureAlgorithm) !== 'eIDASCertificate\AlgorithmIdentifier') {
            throw new \Exception("Unrecognised Signature Algorithm requested", 1);
        }
        $certId = new CertID(
            $signatureAlgorithm,
            $issuerNameHash,
            $issuerKeyHash,
            $serialNumber
        );
        $requestlist[] = new Request($certId);
        if (is_null($nonce)) {
            $this->tbsRequest = new TBSRequest($requestlist);
        } else {
            $this->tbsRequest = new TBSRequest($requestlist, $this->nonce);
        }
    }

    /**
     * [fromDER description]
     * @param  string $der [binary request data]
     * @return [type]      [description]
     */
    public static function fromDER($der)
    {
        $top = [];
        $OCSPRequest = UnspecifiedType::fromDER($der)->asSequence();
        $tbsRequest = TBSRequest::fromDER($OCSPRequest->at(0)->asSequence()->toDER());
        if ($OCSPRequest->hasTagged(0)) {
            throw new ParseException("Cannot support signed Requests", 1);
        }
        $requests = $tbsRequest->getRequests();
        if (sizeof($requests) !== 1) {
            throw new \Exception("Can only accept requests with one target certificate", 1);
        }
        $issuerNameHash = current($requests)->getIssuerNameHash();
        $issuerKeyHash = current($requests)->getIssuerKeyHash();
        $serialNumber = current($requests)->getSerialNumber();
        $hashAlgorithm = current($requests)->getHashAlgorithm();
        return new OCSPRequest(
            $hashAlgorithm,
            $issuerNameHash,
            $issuerKeyHash,
            $serialNumber,
            $tbsRequest->getNonce()
        );
    }

    public static function fromCertificate($subject, $issuer, $algo = 'sha256', $nonce = 'none')
    {
        $subject = new X509Certificate($subject);
        $issuer = new X509Certificate($issuer);
        $issuerNameHash = $subject->getIssuerNameHash();
        $issuerKeyHash = $issuer->getSubjectPublicKeyHash();
        $hashAlgorithm = new AlgorithmIdentifier($algo);
        $serialNumber = $subject->getSerialNumber();
        return new OCSPRequest(
            $hashAlgorithm,
            $issuerNameHash,
            $issuerKeyHash,
            $serialNumber,
            $nonce
        );
    }

    public function getAttributes()
    {
        $attr['requests'] = $this->tbsRequest->getAttributes()['requests'];
        $attr['version'] = $this->tbsRequest->getAttributes()['version'];
        if (! empty($this->nonce)) {
            $attr['nonce'] = bin2hex($this->nonce);
        }
        return $attr;
    }

    public function getBinary()
    {
        return $this->getASN1()->toDER();
    }

    public function getNonce()
    {
        return $this->nonce;
    }

    public function getASN1()
    {
        return new Sequence($this->tbsRequest->getASN1());
    }

    public function getFindings()
    {
        return ([]);
    }

    public function getRequests()
    {
        return $this->tbsRequest->getRequests();
    }
}
