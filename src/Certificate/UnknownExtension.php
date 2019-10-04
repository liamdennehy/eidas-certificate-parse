<?php

namespace eIDASCertificate\Certificate;

use eIDASCertificate\Certificate\ExtensionInterface;
use eIDASCertificate\Finding;
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
        if (empty($this->oid)) {
            throw new Exception("OID not set on unknown extension", 1);
        }
        $name = OID::getName($this->oid);
        if ($name == 'unknown') {
            $name = "'$this->oid'";
        } else {
            $name = "'$name' ($this->oid)";
        }
        $findings = [];
        if ($this->isCritical) {
            $level = 'critical';
            $message =
              "Unhandled extension $name marked critical: ".
              base64_encode($this->binary);
        } else {
            $level = 'warning';
            $message =
              "Unhandled extension $name: ".
              base64_encode($this->binary);
        }
        $findings[] = new Finding(
            'extensions',
            $level,
            $message
        );
        return $findings;
    }

    public function getIsCritical()
    {
        return $this->isCritical;
    }
}
