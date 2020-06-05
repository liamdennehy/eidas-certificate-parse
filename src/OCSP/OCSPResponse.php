<?php

namespace eIDASCertificate\OCSP;

use ASN1\Type\UnspecifiedType;
// use eIDASCertificate\ASN1Interface;
// use eIDASCertificate\AttributeInterface;
// use eIDASCertificate\Extensions;
use eIDASCertificate\OID;
use ASN1\Type\Constructed\Sequence;

// TODO: implements ASN1Interface, AttributeInterface
class OCSPResponse
{

    public function fromDER($der)
    {
        return self::fromASN1(UnspecifiedType::fromDER($der)->asSequence())
    }

    public static function fromSequence($asn1)
    {
        $asn1 = UnspecifiedType::fromDER($der)->asSequence();
        $rb = $asn1->getTagged(0)->asExplicit()->asSequence();
        $responseType = $rb->at(0)->asObjectIdentifier()->oid();
        switch ($responseType) {
          case OID::ocspBasic:
            $response = BasicOCSPResponse::fromSequence(
                UnspecifiedType::fromDER(
                    $rb->at(1)->asOctetString()->string()
                )->asSequence()
            );
            break;

          default:
            throw new \Exception("Unnown responseType OID '$responseType'", 1);

            break;
        }
        return;
        $response = (UnspecifiedType::fromDER(
            $rb->at(1)->asOctetString()->string()
        ))->asSequence();
        $tbsResponseData = ResponseData::fromSequence($response->at(0)->asSequence());
    }
}
