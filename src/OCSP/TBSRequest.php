<?php

namespace eIDASCertificate\OCSP;

use ASN1\Type\UnspecifiedType;
use eIDASCertificate\ASN1Interface;
use eIDASCertificate\AttributeInterface;
use eIDASCertificate\Extensions;
use eIDASCertificate\ParseException;
use ASN1\Type\Constructed\Sequence;
use ASN1\Type\Tagged\ExplicitlyTaggedType;

class TBSRequest implements ASN1Interface, AttributeInterface
{
    private $version;
    private $requestList = [];
    private $nonce;

    public function __construct($requestList, $nonce = null, $version = 1)
    {
        if ($version !== 1) {
            throw new \Exception("Only version 1 OCSP Requests are supported", 1);
        }
        $this->version = $version;
        $this->requestList = $requestList;
        if (! empty($nonce)) {
            $this->nonce = $nonce;
        }
    }

    public static function fromDER($der)
    {
        return self::fromSequence(UnspecifiedType::fromDER($der)->asSequence());
    }

    public static function fromSequence($tbsRequest)
    {
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
            $request = Request::fromSequence($request->asSequence());
            $requests[] = $request;
        }
        if ($tbsRequest->hasTagged(2)) {
            $extensions = new Extensions($tbsRequest->getTagged(2)->asExplicit());
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
            $requests[] = $request->getASN1();
        }
        if (is_null($this->nonce)) {
            return new Sequence(
                new Sequence(...$requests)
            );
        } else {
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
    }

    public function getBinary()
    {
        return $this->getASN1()->toDER();
    }

    public function getRequests()
    {
        return $this->requestList;
    }

    public function getNonce()
    {
        return $this->nonce;
    }

    public function getAttributes()
    {
        $attr['version'] = $this->version;
        foreach ($this->requestList as $request) {
            $attr['requests'][] = $request->getAttributes();
        }
        if (! empty($this->nonce)) {
            $attr['nonce'] = bin2hex($this->nonce);
        }
        return $attr;
    }
}
