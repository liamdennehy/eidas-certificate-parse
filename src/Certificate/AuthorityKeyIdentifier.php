<?php

namespace eIDASCertificate\Certificate;

use eIDASCertificate\Certificate\ExtensionInterface;
use eIDASCertificate\CertificateException;
use ASN1\Type\UnspecifiedType;

/**
 *
 */
class AuthorityKeyIdentifier implements ExtensionInterface
{
    private $binary;
    private $keyIdentifier;

    const type = 'authorityKeyIdentifier';
    const oid = '2.5.29.35';
    const uri = 'https://tools.ietf.org/html/rfc5280#section-4.2.1.1';

    public function __construct($extensionDER)
    {
        $seq = UnspecifiedType::fromDER($extensionDER)->asSequence();
        $tagDER = $seq->at(0)->asTagged()->toDER();
        if (bin2hex($tagDER[0]) != '80') {
            throw new ExtensionException("Unrecognised AuthorityKeyIdentifier Format", 1);
        }
        $tagDER[0] = chr(4);
        $this->keyIdentifier = UnspecifiedType::fromDER($tagDER)->asOctetString()->string();
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

    public function getKeyId()
    {
        return $this->keyIdentifier;
    }
}
