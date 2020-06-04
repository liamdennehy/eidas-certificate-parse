<?php

namespace eIDASCertificate\OCSP;

use ASN1\Type\UnspecifiedType;
// use eIDASCertificate\ASN1Interface;
// use eIDASCertificate\AttributeInterface;
use eIDASCertificate\DistinguishedName;
use eIDASCertificate\Extensions;
use ASN1\Type\Constructed\Sequence;

// TODO: implements ASN1Interface, AttributeInterface
class ResponseData
{
    private $version;
    private $responderId;
    private $producedAt;
    private $singleResponses;
    private $extensions;

    public function __construct(
        $version, $responderId, $producedAt, $singleResponses, $extensions = null
    ) {
      $version = $version;
      $responderId = $responderId;
      $producedAt = $producedAt;
      $singleResponses = $singleResponses;
      $extensions = $extensions;
    }

    public function fromDER($der)
    {
        self::fromSequence(UnspecifiedType::fromDER($der)->asSequence());
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
          case 1:
            $responderId = new DistinguishedName($responderId->asImplicit(4)->string());
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
}
