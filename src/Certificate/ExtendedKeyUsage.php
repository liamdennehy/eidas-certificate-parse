<?php

namespace eIDASCertificate\Certificate;

use eIDASCertificate\Certificate\ExtensionInterface;
use eIDASCertificate\OID;
use ASN1\Type\UnspecifiedType;

/**
 *
 */
class ExtendedKeyUsage implements ExtensionInterface
{
    private $binary;
    private $ekus;
    const type = 'extKeyUsage';
    const oid = '2.5.29.37';
    const uri = 'https://tools.ietf.org/html/rfc5280#section-4.2.1.12';

    public function __construct($asn1Extension)
    {
        $this->ekus = [];
        $ekus = UnspecifiedType::fromDER($asn1Extension)->asSequence();
        foreach ($ekus->elements() as $eku) {
            $ekuOID = $eku->asObjectIdentifier()->oid();
            $ekuName = OID::getName($ekuOID);
            if ($ekuName == 'unknown') {
                throw new ExtensionException("Unrecognised EKU $ekuOID", 1);
            } else {
                $this->ekus[$ekuName] = true;
            }
        }

        $this->binary = $asn1Extension;
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
}
