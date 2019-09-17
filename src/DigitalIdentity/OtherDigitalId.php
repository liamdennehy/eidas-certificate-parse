<?php

namespace eIDASCertificate\DigitalIdentity;

use eIDASCertificate\Certificate\X509Certificate;

/**
 *
 */
class OtherDigitalId implements DigitalIdInterface
{
    private $value;

    public function __construct($value)
    {
        $this->value = $value;
    }

    public function getValue()
    {
        return $this->value;
    }

    public function getType()
    {
        return 'OtherDigitalId';
    }
}
