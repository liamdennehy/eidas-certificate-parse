<?php

namespace eIDASCertificate\Certificate;

use eIDASCertificate\Certificate\ExtensionInterface;
use eIDASCertificate\OID;
use ASN1\Type\UnspecifiedType;

/**
 *
 */
class UnknownExtension implements ExtensionInterface
{
    private $binary;
    private $oid;

    const type = 'unknown';
    const uri = '';

    public function __construct($extensionDER, $extensionOid)
    {
        $this->oid = $extensionOid;
        $this->binary = $extensionDER;
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

    public function getBinary()
    {
        return $this->binary;
    }
}
