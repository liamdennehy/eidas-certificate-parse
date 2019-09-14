<?php

namespace eIDASCertificate\Certificate;

use eIDASCertificate\QCStatements;
use FG\ASN1\ASNObject;

/**
 *
 */
abstract class Extension
{
    public static function fromBinary($binary)
    {
        $extension = ASNObject::fromBinary($binary);
    }
}
