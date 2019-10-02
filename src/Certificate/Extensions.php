<?php

namespace eIDASCertificate\Certificate;

use eIDASCertificate\Certificate;
use eIDASCertificate\Certificate\ExtensionException;
use eIDASCertificate\OID;
use ASN1\Type\UnspecifiedType;

/**
 *
 */
class Extensions implements ParseInterface
{
    private $extensions = [];

    public function __construct($extensionsDER)
    {
        $this->extensions = [];
        $extensionsSequence = UnspecifiedType::fromDER($extensionsDER)->asSequence();
        foreach ($extensionsSequence->elements() as $extension) {
            $extension = $extension->asSequence();
            $v3Extension = Extension::fromBinary($extension->toDER());
            if ($v3Extension) {
                if ($v3Extension->getType() == 'unknown') {
                    $extName = 'unknown-'.$v3Extension->getOID();
                } else {
                    $extName = $v3Extension->getType();
                }
                if (array_key_exists($extName, $this->extensions)) {
                    throw new ExtensionException(
                        "Multiple Certificate Extensions of type " . $extName,
                        1
                    );
                }
                $this->extensions[$extName] = $v3Extension;
            }
        }
        // TODO: Minimum set https://tools.ietf.org/html/rfc5280#section-4.2
    }

    public function setKeyUsage($keyUsageString)
    {
        $this->extensions['keyUsage'] = new KeyUsage($keyUsageString);
    }

    public function getExtensions()
    {
        return $this->extensions;
    }
}
