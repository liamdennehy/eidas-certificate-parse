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
        // $tagDER = $seq->at(0)->asTagged()->toDER();
        // if (bin2hex($tagDER[0]) != '80') {
        //     throw new ExtensionException("Unrecognised SubjectKeyIdentifier Format", 1);
        // }
        // $tagDER[0] = chr(4);
        // $this->keyIdentifier = UnspecifiedType::fromDER($tagDER)->asOctetString()->string();
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
