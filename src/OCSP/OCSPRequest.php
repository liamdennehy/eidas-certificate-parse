<?php

namespace eIDASCertificate\OCSP;

use ASN1\Type\UnspecifiedType;
use ASN1\Type\Constructed\Sequence;
use eIDASCertificate\Certificate\Extensions;
use eIDASCertificate\AttributeInterface;
use eIDASCertificate\ParseInterface;
use eIDASCertificate\ASN1Interface;

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
    public function __construct()
    {
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
        $tbsRequest = $OCSPRequest->at(0)->asSequence();
        $tbsRequestDER = $tbsRequest->toDER();
        $tbsRequestidx = 0;
        if ($tbsRequest->hasTagged(0)) {
            // TODO: Throw error as unsupported, would only be present if not "1"
            $version = $tbsRequest->getTagged(0)->asExplicit()->asInteger()->intNumber();
            $tbsRequestidx++;
        } else {
            $version = 1;
        }
        if ($tbsRequest->hasTagged(1)) {
            // TODO: Throw error as unsupported
            $requestorName = $tbsRequest->getTagged(1)->asGeneralName()->string();
            $tbsRequestidx++;
        }
        $requestList = $tbsRequest->at($tbsRequestidx)->asSequence();
        if ($requestList->count() > 1) {
            throw new \Exception("Too many requests in OCSPRequest object", 1);
        }
        foreach ($requestList->elements() as $request) {
            $request = Request::fromDER($request->toDER());
            $requests[] = $request;
        }
        if ($tbsRequest->hasTagged(2)) {
            $extensionsDER = $tbsRequest->getTagged(2)->asExplicit()->asSequence()->toDER();
            $extensions = new Extensions(
                $extensionsDER
            );
            // $findings = array_merge($findings, $this->extensions->getFindings());

            // $extensions = $tbsRequest->getTagged(2)->asExplicit()->asSequence();
        }
        $parsed['b64'] = [
      'OCSPRequest' => base64_encode($OCSPRequest->toDER()),
      'tbsRequest' => base64_encode($tbsRequestDER),
      'extensions' => base64_encode($extensions->getBinary()),
      'requestList' => base64_encode($requestList->toDER()),
    ];
        foreach ($requests as $value) {
            $parsed['b64']['requests'][] = base64_encode($value->getBinary());
        }
        $parsed['requestHash'] = hash('sha256', $der);
        return $parsed;
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
        return (new Sequence(new Sequence))->toDER();
    }

    public function getFindings()
    {
        return ([]);
    }
}
