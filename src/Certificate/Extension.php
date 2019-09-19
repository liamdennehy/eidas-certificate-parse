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
        if (get_class($extension[1]) == "FG\ASN1\Universal\Boolean") {
            $isCritical = ($extension[1]->getContent() === "TRUE");
            $extnValue = hex2bin($extension[2]->getContent());
        } else {
            $isCritical = false;
            $extnValue = hex2bin($extension[1]->getContent());
        }
        $extensionName = OID::getName($extensionOid);
        // print $extensionName . ": " . base64_encode($extnValue) .PHP_EOL;
        switch ($extensionName) {
          case 'basicConstraints':
            // TODO: Properly handle Basic Constraints
            return new BasicConstraints($extnValue);
            break;
          case 'preCertPoison':
            return new PreCertPoison($extnValue);
            // TODO: Properly handle poisoned certificates
            break;
          case 'keyUsage':
            return false; // Canot parse bit strings with current library
            // return new KeyUsage($extnValue);
            break;
          case 'authorityKeyIdentifier':
            // TODO: Implement AKI
            return new AuthorityKeyIdentifier($extnValue);
            break;
          case 'extKeyUsage':
            // TODO: Implement EKU
            return new ExtendedKeyUsage($extnValue);
            break;

          default:
            if ($extension[1]->getContent() === "TRUE") {
                throw new ExtensionException(
                    "Unrecognised Critical Extension OID '$extensionOid' ($extensionName), cannot proceed: '" .
                    base64_encode($extension->getBinary()).
                    "'",
                    1
                );
            } else {
                return new UnknownExtension($extension->getbinary());
            }
            break;
        }
    }
}
