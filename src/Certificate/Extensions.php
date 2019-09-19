<?php

namespace eIDASCertificate\Certificate;

use eIDASCertificate\Certificate;
use eIDASCertificate\Certificate\ExtensionException;
use eIDASCertificate\OID;
use FG\ASN1\ASNObject;

/**
 *
 */
 class Extensions
{
    private $extensions = [];

    public function __construct($asn1Extensions)
    {
      $this->extensions = [];
      $this->asn1Object = ASNObject::fromBinary($asn1Extensions);
      foreach ($this->asn1Object as $extension) {
          $v3Extension = Extension::fromASNObject($extension);
          if ($v3Extension->getType() != 'unknown') {
            if (array_key_exists($v3Extension->getType(), $this->extensions)) {
              throw new ExtensionException(
                "Multiple Certificate Extensions of type " . $v3Extension->getType(),
                1
              );
            } else {
              $this->extensions[$v3Extension->getType()] = $extension;
            }
          } else {
            $this->extensions[$v3Extension->getType().'-'.$v3Extension->getOID()] = $extension;
            // code...
          }
      }
      // var_dump($this->extensions);
    }
}
