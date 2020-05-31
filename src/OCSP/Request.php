<?php

namespace eIDASCertificate\OCSP;

use ASN1\Type\UnspecifiedType;
use eIDASCertificate\ASN1Interface;

class Request implements ASN1Interface
{
    private $binary;

    public function __construct($subject, $issuer, $algo = 'sha256')
    {

    }
    public static function fromDER($der)
    {
        $request = UnspecifiedType::fromDER($der)->asSequence();
        $this->binary = $der;
    }

    public function getBinary()
    {
        return $this->binary;
    }
}
