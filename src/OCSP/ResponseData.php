<?php

namespace eIDASCertificate\OCSP;

use ASN1\Type\UnspecifiedType;
use eIDASCertificate\ASN1Interface;
use eIDASCertificate\AttributeInterface;
use eIDASCertificate\DistinguishedName;
use eIDASCertificate\Extensions;
use ASN1\Type\Constructed\Sequence;
use ASN1\Type\Tagged\ImplicitlyTaggedType;
use ASN1\Type\Tagged\ExplicitlyTaggedType;
use ASN1\Type\Primitive\GeneralizedTime;
use ASN1\Type\Primitive\Integer;
use ASN1\Type\Primitive\OctetString;

class ResponseData implements ASN1Interface, AttributeInterface
{
    private $version;
    private $responderId;
    private $producedAt;
    private $singleResponses;
    private $extensions;

    public function __construct(
        $version,
        $responderId,
        $producedAt,
        $singleResponses,
        $extensions = null
    ) {
        $this->version = $version;
        $this->responderId = $responderId;
        $this->producedAt = $producedAt;
        $this->singleResponses = $singleResponses;
        $this->extensions = $extensions;
    }

    public static function fromDER($der)
    {
        return self::fromSequence(UnspecifiedType::fromDER($der)->asSequence());
    }

    public static function fromSequence($tbsResponseData)
    {
        $idx = 0;
        if ($tbsResponseData->at($idx)->tag() == 0) {
            $version = $tbsResponseData->at($idx)->asInteger()->integer();
            $tbsResponseData = $tbsResponseData->withoutElement($idx);
            $idx++;
            throw new \Exception("ResponData version $version not supported", 1);
        } else {
            $version = 1;
        }
        $responderId = $tbsResponseData->at($idx++);
        switch ($responderId->tag()) {
          case 1:
            $responderId = new DistinguishedName($responderId->asImplicit(16)->at(0));
            break;
          case 2:
            $responderId = $responderId->asImplicit(4)->string();
            break;
          default:
            throw new \Exception("Unkown RespondeID tag ".$responderId->tag(), 1);

            break;

        }
        $producedAt = $tbsResponseData->at($idx++)->asGeneralizedTime()->dateTime();
        $responses = $tbsResponseData->at($idx++)->asSequence();
        foreach ($responses->elements() as $responseElement) {
            $singleResponses[] = SingleResponse::fromSequence($responseElement->asSequence());
        }
        if ($tbsResponseData->has($idx) && $tbsResponseData->at($idx)->tag() == 1) {
            $extensions = new Extensions($tbsResponseData->at($idx)->asExplicit()->asSequence()->toDER());
            $idx++;
        } else {
            $extensions = null;
        }
        return new ResponseData(
            $version,
            $responderId,
            $producedAt,
            $singleResponses,
            $extensions
        );
    }

    public function getBinary()
    {
        return $this->getASN1()->toDER();
    }

    public function getASN1($value='')
    {
        $asn1 = new Sequence();
        if ($this->version <> 1) {
            $asn1 = $asn1->withAppended(new ExplicitlyTaggedType(0, new Integer($this->version - 1)));
        };
        if (is_string($this->responderId)) {
            $asn1 = $asn1->withAppended(new ImplicitlyTaggedType(2, new Sequence(new OctetString($this->responderId))));
        } else {
            $asn1 = $asn1->withAppended(new ImplicitlyTaggedType(1, $this->responderId->getASN1()));
        }
        $asn1 = $asn1->withAppended(new GeneralizedTime($this->producedAt));
        foreach ($this->singleResponses as $response) {
            $responses[] = $response->getASN1();
        }
        $asn1 = $asn1->withAppended(new Sequence(...$responses));
        if (! empty($this->extensions)) {
            $asn1 = $asn1->withAppended(new ExplicitlyTaggedType(1, $this->extensions->getASN1()));
        }
        return $asn1;
    }

    public function getAttributes()
    {
        $attr['producedAt'] = (int)($this->producedAt->format('U'));
        foreach ($this->singleResponses as $response) {
            $attr['responses'][] = $response->getAttributes();
        }
        if (! empty($this->extensions) && array_key_exists('ocspNonce', $this->extensions->getExtensions())) {
            $attr['nonce'] = bin2hex($this->extensions->getExtensions()['ocspNonce']->getAttributes()['nonce']);
        }
        return $attr;
    }
}
