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
use eIDASCertificate\Algorithm\AlgorithmIdentifier;

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
    private $subjects;

    public function __construct(
        $signatureAlgorithm,
        $issuerNameHashes,
        $issuerKeyHashes,
        $serialNumbers,
        $nonce = 'none'
    ) {
        if (is_object($signatureAlgorithm) && get_class($signatureAlgorithm) !== 'eIDASCertificate\Algorithm\AlgorithmIdentifier') {
            throw new \Exception("Unrecognised Signature Algorithm requested", 1);
        }
        if ($nonce == 'auto') {
            $this->nonce = random_bytes(16);
        } elseif ($nonce == 'none') {
            $this->nonce == null;
        } else {
            $this->nonce = $nonce;
        }
        if (! is_array($serialNumbers)) {
            $serialNumbers = [$serialNumbers];
        }
        if (! is_array($issuerNameHashes)) {
            $issuerNameHashes = [$issuerNameHashes];
        }
        if (! is_array($issuerKeyHashes)) {
            $issuerKeyHashes = [$issuerKeyHashes];
        }
        if (((array_keys($serialNumbers) !== array_keys($issuerNameHashes)) || (array_keys($issuerNameHashes) !== array_keys($issuerKeyHashes)))) {
            throw new \Exception("Unmatched arrays provided to OCSPRequest", 1);
        }
        if (is_string($signatureAlgorithm)) {
            $signatureAlgorithm = new AlgorithmIdentifier($signatureAlgorithm);
        }
        $certIDs = [];

        foreach ($serialNumbers as $key => $serialNumber) {
            $certId = new CertID(
                $signatureAlgorithm,
                $issuerNameHashes[$key],
                $issuerKeyHashes[$key],
                $serialNumbers[$key]
            );
            $requestlist[] = new Request($certId);
        }
        if (is_null($nonce)) {
            $this->tbsRequest = new TBSRequest($requestlist);
        } else {
            $this->tbsRequest = new TBSRequest($requestlist, $this->nonce);
        }
    }

    public static function fromDER($der)
    {
        return self::fromSequence(UnspecifiedType::fromDER($der)->asSequence());
    }

    public static function fromSequence($OCSPRequest)
    {
        $top = [];
        $tbsRequest = TBSRequest::fromSequence($OCSPRequest->at(0)->asSequence());
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

    public static function fromCertificate($subjects, $algo = 'sha256', $nonce = 'none')
    {
        if (! is_array($subjects)) {
            $subjects = [$subjects];
        }
        $serialNumbers = [];
        foreach ($subjects as $subject) {
            if ((! is_object($subject) || (! get_class($subject) == 'eIDASCertificate\Certificate\X509Certificate'))) {
                throw new \Exception("OCSP Request requires X509Certificate Objects with one issuer attached each", 1);
            } elseif (! $subject->hasIssuers() || sizeof($subject->getIssuers()) <> 1) {
                throw new \Exception("OCSP Request requires X509Certificate Objects with one issuer attached each", 1);
            } else {
                $serialNumbers[] = $subject->getSerialNumber();
                $issuerNameHashes[] = $subject->getIssuerNameHash();
                $issuerKeyHashes[] = $subject->getIssuerPublicKeyHash();
            }
        }
        $hashAlgorithm = new AlgorithmIdentifier($algo);
        $request = new OCSPRequest(
            $hashAlgorithm,
            $issuerNameHashes,
            $issuerKeyHashes,
            $serialNumbers,
            $nonce
        );
        $request->setSubjects($subjects);
        return $request;
    }

    protected function setSubjects($subjects)
    {
        $this->subjects = [];
        foreach ($subjects as $subject) {
            $this->subjects[$subject->getIdentifier()] = $subject;
        }
    }

    public function getSubjects()
    {
        if ($this->hasSubjects()) {
            return $this->subjects;
        } else {
            return null;
        }
    }

    public function hasSubjects()
    {
        return (! empty($this->subjects));
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
