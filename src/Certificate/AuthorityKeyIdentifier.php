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
        // var_dump([
        //   bin2hex($tagDER[0]),
        //   bin2hex(chr(0x80))
        // ]);
        switch ($tagDER[0]) {
          case chr(0x80):
            $tagDER[0] = chr(4);
            $this->keyIdentifier = UnspecifiedType::fromDER($tagDER)->asOctetString()->string();
            break;

          default:
            var_dump(base64_encode($extensionDER));
            throw new ExtensionException("Unrecognised AuthorityKeyIdentifier Format", 1);
            // code...
            break;
        }
        // if ($tagDER[0] != chr(0x80)) {
        // }
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
