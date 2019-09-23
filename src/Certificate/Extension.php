<?php

namespace eIDASCertificate\Certificate;

use eIDASCertificate\Certificate\ExtensionException;
use eIDASCertificate\Certificate\AuthorityKeyIdentifier;
use eIDASCertificate\Certificate\UnknownExtension;
use eIDASCertificate\OID;
use ASN1\Type\UnspecifiedType;

/**
 *
 */
abstract class Extension
{
    public static function fromBinary($extensionDER)
    {
        $extension = UnspecifiedType::fromDER($extensionDER)->asSequence();
        $extensionOid = $extension->at(0)->asObjectIdentifier()->oid();
        if ($extension->at(1)->isType(1)) {
            $isCritical = $extension->at(1)->asBoolean()->value();
            // var_dump($extension->at(2)->asOctetString());
            $extnValue = $extension->at(2)->asOctetString()->string();
        } else {
            $isCritical = false;
            $extnValue = $extension->at(1)->asOctetString()->string();
        }
        $extensionName = OID::getName($extensionOid);
        // print "$extensionOid ($extensionName): " . base64_encode($extnValue) .PHP_EOL;
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
          case 'crlDistributionPoints':
            // TODO: Implement CDPs
            return new CRLDistributionPoints($extnValue);
            break;
          case 'qcStatements':
            // TODO: Implemented on certificate object
            return false;
            break;

          default:
            if ($isCritical) {
                throw new ExtensionException(
                    "Unrecognised Critical Extension OID '$extensionOid' ($extensionName), cannot proceed: '" .
                    base64_encode($extension->getBinary()).
                    "'",
                    1
                );
            } else {
                return new UnknownExtension(
                    $extnValue,
                    $extensionOid
                );
            }
            break;
        }
    }
}
