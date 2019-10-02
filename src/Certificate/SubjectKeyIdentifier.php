<?php

namespace eIDASCertificate\Certificate;

use eIDASCertificate\Certificate\ExtensionInterface;
use eIDASCertificate\CertificateException;
use ASN1\Type\UnspecifiedType;

/**
 *
 */
class SubjectKeyIdentifier implements ExtensionInterface
{
    private $binary;
    private $keyIdentifier;

    const type = 'subjectKeyIdentifier';
    const oid = '2.5.29.14';
    const uri = 'https://tools.ietf.org/html/rfc5280#section-4.2.1.2';

    public function __construct($extensionDER)
    {
        $this->keyIdentifier = UnspecifiedType::fromDER($extensionDER)->asOctetString()->string();
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

    public function getDescription()
    {
        return "This is a SubjectKeyIDentifier extension";
    }
}
