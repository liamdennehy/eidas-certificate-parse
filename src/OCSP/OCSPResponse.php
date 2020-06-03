<?php

namespace eIDASCertificate\OCSP;

use ASN1\Type\UnspecifiedType;
// use eIDASCertificate\ASN1Interface;
// use eIDASCertificate\AttributeInterface;
// use eIDASCertificate\Extensions;
use ASN1\Type\Constructed\Sequence;

// TODO: implements ASN1Interface, AttributeInterface
class OCSPResponse
{
    public static function fromDER($der)
    {
        $asn1 = UnspecifiedType::fromDER($der)->asSequence();
        $rb = $asn1->getTagged(0)->asExplicit()->asSequence();
        $rt = $rb->at(0)->asObjectIdentifier()->oid();
        $response = (UnspecifiedType::fromDER($rb->at(1)->asOctetString()->string()))->asSequence();
        $tbsResponseData = ResponseData::fromSequence($response->at(0)->asSequence());
    }

}
