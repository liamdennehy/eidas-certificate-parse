<?php

namespace eIDASCertificate\OCSP;

use ASN1\Type\UnspecifiedType;
use eIDASCertificate\ASN1Interface;
use eIDASCertificate\AttributeInterface;
use eIDASCertificate\Extensions;
use ASN1\Type\Constructed\Sequence;

class Request implements ASN1Interface, AttributeInterface
{
    private $binary;
    private $certId;
    private $extensions;

    /**
     * [__construct description]
     * @param CertID $certId     [description]
     * @param Extensions $extensions [description]
     */
    public function __construct(CertID $certId, Extensions $extensions = null)
    {
        $this->certId = $certId;
        $this->extensions = $extensions;
    }

    public static function fromDER($der)
    {
        return self::fromSequence(UnspecifiedType::fromDER($der)->asSequence());
    }

    public static function fromSequence($request)
    {
        $certId = CertID::fromSequence($request->at(0)->asSequence());
        if ($request->hasTagged(0)) {
            $extensions = new Extensions($request->getTagged(0)->asExplicit()->toDER());
        } else {
            $extensions = null;
        }
        return new Request($certId, $extensions);
    }

    public function getASN1()
    {
        $seq = new Sequence($this->certId->getASN1());
        if (! empty($this->extensions)) {
            $seq = $seq->withAppended(new ExplicitlyTaggedType(0, $this->extensions->getASN1()));
        }
        return $seq;
    }

    public function getBinary()
    {
        return $this->getASN1()->toDER();
    }

    public function getExtensions()
    {
        return $this->extensions;
    }

    public function getNonce()
    {
        if (is_array($this->extensions) && array_key_exists('ocspNonce', $this->extensions)) {
            return $this->extensions['ocspNonce']->getNonce();
        }
    }

    public function getHashAlgorithm()
    {
        return $this->certId->getHashAlgorithm();
    }

    public function getSerialNumber()
    {
        return $this->certId->getSerialNumber();
    }

    public function getIssuerKeyHash()
    {
        return $this->certId->getIssuerKeyHash();
    }

    public function getIssuerNameHash()
    {
        return $this->certId->getIssuerNameHash();
    }

    public function getAttributes()
    {
        $attr = $this->certId->getAttributes();
        if (! empty($this->getNonce())) {
            $attr['nonce'] = $this->getNonce();
        }
        return $attr;
    }

    public function getCertIdIdentifier()
    {
        return $this->certId->getIdentifier();
    }
}
