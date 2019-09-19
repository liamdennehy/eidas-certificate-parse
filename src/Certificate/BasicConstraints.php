<?php

namespace eIDASCertificate\Certificate;

use eIDASCertificate\Certificate\ExtensionInterface;
use eIDASCertificate\OID;
use FG\ASN1\ASNObject;

/**
 *
 */
 class BasicConstraints implements ExtensionInterface
{
    private $binary;
    const type = 'basicConstraints';
    const oid = '2.5.29.19';
    const uri = 'https://tools.ietf.org/html/rfc5280#section-4.2.1.9';

    public function __construct($asn1Extension)
    {

    }

    public function getType()
    {
        return self::type;
    }

    public function getURI()
    {
        return self::uri;
    }
}
