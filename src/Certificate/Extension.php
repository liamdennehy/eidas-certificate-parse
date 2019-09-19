<?php

namespace eIDASCertificate\Certificate;

use eIDASCertificate\Certificate\ExtensionException;
use eIDASCertificate\Certificate\AuthorityKeyIdentifier;
use eIDASCertificate\Certificate\UnknownExtension;
use eIDASCertificate\OID;
use FG\ASN1\ASNObject;

/**
 *
 */
abstract class Extension
{
    public static function fromASNObject($extension)
    {
        $extensionOid = $extension[0]->getContent();
        $extensionName = OID::getName($extensionOid);
        switch ($extensionName) {
          case 'basicConstraints':
            return new BasicConstraints($extension->getbinary());
            // TODO: Properly Basic Constraints
            break;
          case 'preCertPoison':
            return new PreCertPoison($extension->getbinary());
            // TODO: Properly handle poisoned certificates
            break;
          case 'keyUsage':
            return new KeyUsage($extension->getbinary());
            break;
          // case 'authorityKeyIdentifier':
          //   return new AuthorityKeyIdentifier($extension->getbinary());
          //   break;

          default:
            if ($extension[1]->getContent() === "TRUE") {
              throw new ExtensionException("Unrecognised Critical Extension OID '$extensionOid' ($extensionName), cannot proceed", 1);
            } else {
                return new UnknownExtension($extension->getbinary());
            }
            break;
        }
        // var_dump([$extension[0]->getContent(), $name]);
        // return($extention);
    }
}
