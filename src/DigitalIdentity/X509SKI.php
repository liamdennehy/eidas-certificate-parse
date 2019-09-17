<?php

namespace eIDASCertificate\DigitalIdentity;

use eIDASCertificate\Certificate\X509Certificate;

/**
 *
 */
class X509SKI implements DigitalIdInterface
{
    private $ski;

    public function __construct($value)
    {
        $this->ski = $value;
    }

    public function getSKI()
    {
        return $this->ski;
    }

    public function getSKIBase64()
    {
        return base64_encode($this->ski);
    }

    public function getType()
    {
        return 'X509SKI';
    }
}
