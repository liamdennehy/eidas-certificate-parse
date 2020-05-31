<?php

namespace eIDASCertificate\OCSP;

use ASN1\Type\UnspecifiedType;
use eIDASCertificate\ASN1Interface;
use eIDASCertificate\Certificate\Extensions;
use ASN1\Type\Constructed\Sequence;

class Request implements ASN1Interface
{
    private $binary;
    private $certId;
    private $extensions;

    /**
     * [__construct description]
     * @param CertID $certId     [description]
     * @param [type] $extensions [description]
     */
    public function __construct(CertID $certId, Extensions $extensions = null)
    {
        $this->certId = $certId;
        $this->extensions = $extensions;
    }

    public static function fromDER($der)
    {
        $asn1 = UnspecifiedType::fromDER($der)->asSequence();
        $certId = CertID::fromDER($asn1->at(0)->toDER());
        return new Request($certId);
    }

    public function getASN1()
    {
        return new Sequence($this->certId->getASN1());
    }


    public function getBinary()
    {
        return $this->getASN1()->toDER();
    }
}
