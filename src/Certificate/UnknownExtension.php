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
    private $isCritical;
    private $findings = [];

    const type = 'unknown';
    const uri = '';

    public function __construct($extensionDER, $isCritical = false)
    {
        $this->isCritical = $isCritical;
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

    public function setOID($oid)
    {
        $this->oid = $oid;
    }

    public function getBinary()
    {
        return $this->binary;
    }

    public function getDescription()
    {
        return "I know nothing about this extension";
    }

    public function getFindings()
    {
        if ($this->isCritical) {
            new Finding(
                'extensions',
                'error',
                "Unhandled extension '$this->oid' marked critical: ".
                base64_encode($this->binary)
            );
        }
        return [];
    }

    public function getIsCritical()
    {
        return $this->isCritical;
    }
}
