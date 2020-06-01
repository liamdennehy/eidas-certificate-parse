<?php

namespace eIDASCertificate\OCSP;

use ASN1\Type\UnspecifiedType;
use eIDASCertificate\ASN1Interface;
use eIDASCertificate\Certificate\Extensions;
use eIDASCertificate\ParseException;
use ASN1\Type\Constructed\Sequence;
use ASN1\Type\Tagged\ExplicitlyTaggedType;

class TBSRequest implements ASN1Interface
{
    private $version = 1;
    private $requestList = [];
    private $nonce;

    public function __construct($requestList, $nonce = null)
    {
        $this->requestList = $requestList;
        if (! empty($nonce)) {
            $this->nonce = $nonce;
        }
    }

    public static function fromDER($der)
    {
        $tbsRequest = UnspecifiedType::fromDER($der)->asSequence();
        $idx = 0;
        if ($tbsRequest->hasTagged(0)) {
            if ($version !== 1) {
                throw new ParseException(
                    "Unsupported OCSPRequest tbsRequest version '".$version."'",
                    1
                );
            }
            $version = $tbsRequest->getTagged(0)->asExplicit()->asInteger()->intNumber();
            $idx++;
        } else {
            $version = 1;
        }
        if ($tbsRequest->hasTagged(1)) {
            throw new ParseException(
                "Unsupported GeneralName field in OCSPRequest TBSRequest",
                1
            );
            $idx++;
        }
        $requestList = $tbsRequest->at($idx)->asSequence();
        foreach ($requestList->elements() as $request) {
            $request = Request::fromDER($request->toDER());
            $requests[] = $request;
        }
        if ($tbsRequest->hasTagged(2)) {
            $extensions = new Extensions($tbsRequest->getTagged(2)->asExplicit()->toDER());
            $extensionsDER = $tbsRequest->getTagged(2)->asExplicit()->asSequence()->toDER();
            $extensions = new Extensions(
                $extensionsDER
            );
            if (sizeof($extensions->getExtensions()) !== 1) {
                throw new ParseException(
                    "Expected 1 extension, got ".sizeof($extensions->getExtensions()),
                    1
                );
            }
        }
        return new TBSRequest(
            $requests,
            $extensions->getExtensions()['ocspNonce']->getNonce()
        );
    }

    public function getASN1()
    {
        foreach ($this->requestList as $request) {
            $requests[] = UnspecifiedType::fromDER($request->getBinary())->asSequence();
        }
        return new Sequence(
            new Sequence(...$requests),
            new ExplicitlyTaggedType(
                2,
                new Sequence(
                  (OCSPNonce::fromValue($this->nonce))->getASN1()
              )
            )
        );
    }
    public function getBinary()
    {
        return $this->getASN1()->toDER();
    }
}