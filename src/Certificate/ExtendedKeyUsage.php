<?php

namespace eIDASCertificate\Certificate;

use eIDASCertificate\Certificate\ExtensionInterface;
use eIDASCertificate\OID;
use eIDASCertificate\Finding;
use ASN1\Type\UnspecifiedType;

/**
 *
 */
class ExtendedKeyUsage implements ExtensionInterface
{
    private $binary;
    private $ekus = [];
    private $findings = [];
    private $isCritical;

    const type = 'extKeyUsage';
    const oid = '2.5.29.37';
    const uri = 'https://tools.ietf.org/html/rfc5280#section-4.2.1.12';

    public function __construct($extensionDER, $isCritical = false)
    {
        $this->isCritical = $isCritical;
        $this->ekus = [];
        $ekus = UnspecifiedType::fromDER($extensionDER)->asSequence();
        foreach ($ekus->elements() as $eku) {
            $ekuOID = $eku->asObjectIdentifier()->oid();
            $ekuName = OID::getName($ekuOID);
            if ($ekuName == 'unknown') {
                $this->findings[] = new Finding(
                    self::type,
                    'error',
                    "Unrecognised ExtendedKeyUsage: ".
                  base64_encode($extensionDER)
                );
                $this->ekus['unknown'] = true;
            } else {
                $this->ekus[$ekuName] = true;
            }
        }
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

    public function getBinary()
    {
        return $this->binary;
    }

    public function getEKUs()
    {
    }

    public function forPurpose($purpose)
    {
        if (array_key_exists($purpose, $this->ekus)) {
            return $this->ekus[$purpose];
        } else {
            return false;
        }
    }

    public function getDescription()
    {
        return "This is an ExtendedKeyUsage extension";
    }

    public function getFindings()
    {
        return $this->findings;
    }

    public function getIsCritical()
    {
        return $this->isCritical;
    }
}
