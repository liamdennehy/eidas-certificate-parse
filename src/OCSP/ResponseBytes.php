<?php

namespace eIDASCertificate\OCSP;

use ASN1\Type\UnspecifiedType;
// use eIDASCertificate\ASN1Interface;
// use eIDASCertificate\AttributeInterface;
// use eIDASCertificate\Extensions;
use ASN1\Type\Constructed\Sequence;

// TODO: implements ASN1Interface, AttributeInterface
class ResponseBytes
{
    private $certId;
    private $certStatus;
    private $thisUpdate;
    private $nextUpdate;
    private $singleExtensions = [];

    public static function fromDER($der)
    {
    }
}
