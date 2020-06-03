<?php

namespace eIDASCertificate\OCSP;

use ASN1\Type\UnspecifiedType;
// use eIDASCertificate\ASN1Interface;
// use eIDASCertificate\AttributeInterface;
// use eIDASCertificate\Extensions;
use ASN1\Type\Constructed\Sequence;

// TODO: implements ASN1Interface, AttributeInterface
class ResponseData
{
    public static function fromSequence($tbsResponseData)
    {
        var_dump(base64_encode($tbsResponseData->toDER()));
        $idx = 0;
        if ($tbsResponseData->hasTagged(0)) {
            $idx++;
        }
        $responderId = $tbsResponseData->at($idx++);
        var_dump(base64_encode($responderId->toDER()));
        $producedAt = $tbsResponseData->at($idx++)->asGeneralizedTime()->dateTime();
        var_dump($producedAt);
        $responses = $tbsResponseData->at($idx++)->asSequence();
        foreach ($responses->elements() as $responseElement) {
            var_dump(base64_encode($responseElement->toDER()));
            $singleResponses[] = SingleResponse::fromDER($responseElement->toDER());
        }
    }
}
