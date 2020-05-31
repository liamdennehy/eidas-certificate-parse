<?php

namespace eIDASCertificate\OCSP;

use ASN1\Type\UnspecifiedType;
use ASN1\Type\Constructed\Sequence;
use eIDASCertificate\Certificate\Extensions;
use eIDASCertificate\OCSP\TBSRequest;
use eIDASCertificate\AttributeInterface;
use eIDASCertificate\ParseInterface;
use eIDASCertificate\ASN1Interface;
use eIDASCertificate\ParseException;

class OCSPRequest implements
    AttributeInterface,
    ParseInterface,
    ASN1Interface
{
    private $attributes = [];
    private $version;
    private $binary;
    private $tbsRequest;

    // TODO: Actually implement OCSP Request creation
    // public function __construct($crtSubject, $withNonce = false)

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
    }

    public function getAttributes()
    {
        if (empty($this->attributes)) {
            $this->attributes['version'] = $this->version;
            foreach ($this->requests as $request) {
                $this->attributes['requests'][] = base64_encode($request->getBinary);
            }
        }
        return $this->attributes;
    }

    public function getBinary()
    {
        return $this->getASN1()->toDER();
    }



    public function getASN1()
    {
        return (new Sequence(new Sequence));
    }

    public function getFindings()
    {
        return ([]);
    }
}
