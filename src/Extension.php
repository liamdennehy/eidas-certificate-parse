<?php

namespace eIDASCertificate;

use eIDASCertificate\ExtensionException;
use eIDASCertificate\Certificate\AuthorityInformationAccess;
use eIDASCertificate\Certificate\AuthorityKeyIdentifier;
use eIDASCertificate\Certificate\BasicConstraints;
use eIDASCertificate\Certificate\CertificatePolicies;
use eIDASCertificate\Certificate\CRLDistributionPoints;
use eIDASCertificate\Certificate\ExtendedKeyUsage;
use eIDASCertificate\Certificate\KeyUsage;
use eIDASCertificate\Certificate\OCSPNoCheck;
use eIDASCertificate\Certificate\PreCertPoison;
use eIDASCertificate\Certificate\SCTList;
use eIDASCertificate\Certificate\SubjectAltName;
use eIDASCertificate\Certificate\SubjectKeyIdentifier;
use eIDASCertificate\UnknownExtension;
use eIDASCertificate\OCSP\OCSPNonce;
use eIDASCertificate\Extensions\QCStatements;
use eIDASCertificate\OID;
use ASN1\Type\UnspecifiedType;

/**
 *
 */
abstract class Extension
{
    public static function fromBinary($extensionDER)
    {
        return self::fromSequence(UnspecifiedType::fromDER($extensionDER)->asSequence());
    }

    public static function fromSequence($extension)
    {
        $idx = 0;
        $extensionOid = $extension->at($idx++)->asObjectIdentifier()->oid();
        if ($extension->at($idx)->isType(1)) {
            $isCritical = $extension->at($idx++)->asBoolean()->value();
        } else {
            $isCritical = false;
        }
        $extnValue = $extension->at($idx++)->asOctetString()->string();
        $extensionName = OID::getName($extensionOid);
        switch ($extensionName) {
          case 'basicConstraints':
            // TODO: Properly handle Basic Constraints
            return new BasicConstraints($extnValue, $isCritical);
            break;
          case 'preCertPoison':
            return new PreCertPoison($extnValue, $isCritical);
            // TODO: Properly handle poisoned certificates
            break;
          case 'keyUsage':
            return new KeyUsage($extnValue, $isCritical);
            break;
          case 'authorityInfoAccess':
            return new AuthorityInformationAccess($extnValue, $isCritical);
            break;
          case 'subjectKeyIdentifier':
            return new SubjectKeyIdentifier($extnValue, $isCritical);
            break;
          case 'authorityKeyIdentifier':
            return new AuthorityKeyIdentifier($extnValue, $isCritical);
            break;
          case 'subjectAltName':
            return new SubjectAltName($extnValue, $isCritical);
            break;
          case 'certificatePolicies':
            return new CertificatePolicies($extnValue, $isCritical);
            break;
          case 'extKeyUsage':
            // TODO: Implement EKU
            return new ExtendedKeyUsage($extnValue, $isCritical);
            break;
          case 'crlDistributionPoints':
            // TODO: Implement CDPs
            return new CRLDistributionPoints($extnValue, $isCritical);
            break;
          case 'qcStatements':
            return new QCStatements($extnValue, $isCritical);
            break;
          case 'ocspNonce':
            return new OCSPNonce($extnValue, $isCritical);
            break;
          case 'ocspNoCheck':
            return new OCSPNoCheck($extnValue, $isCritical);
            break;
          case 'SCTList':
            return new SCTList($extnValue, $isCritical);
            break;
          // case 'policyConstraints':
            // TODO: Implement policyConstraints QCStatement
            // return false;
            // break;

          default:
                $extension = new UnknownExtension(
                    $extnValue,
                    $isCritical
                );
                $extension->setOID($extensionOid);
                return $extension;
            // }
            break;
        }
    }
}
