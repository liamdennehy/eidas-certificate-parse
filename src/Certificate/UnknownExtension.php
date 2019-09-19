<?php

namespace eIDASCertificate\Certificate;

use eIDASCertificate\Certificate\ExtensionInterface;
use eIDASCertificate\OID;
use FG\ASN1\ASNObject;

/**
 *
 */
 class UnknownExtension implements ExtensionInterface
{
    private $binary;
    const type = 'unknown';
    const uri = '';

    public function __construct($binary)
    {
      $object = ASNObject::fromBinary($binary);
      $this->binary = $binary;
      $this->oid = $object[0]->getContent();

    }

    public function getType()
    {
        return self::type;
    }

    public function getURI()
    {
        return self::uri;
    }

    public function getOID()
    {
        return $this->oid;
    }
}
