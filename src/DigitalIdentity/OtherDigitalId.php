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
        $value = trim($value);
        if (! empty($value)) {
            $this->value = $value;
        } else {
            return null;
        }
    }

    public function getValue()
    {
        return $this->value;
    }

    public function getType()
    {
        return 'OtherDigitalId';
    }

    public function getIdentifier()
    {
        // code...
    }
}
