<?php

namespace eIDASCertificate;

/**
 *
 */
class OID
{
    const qcStatements            = '1.3.6.1.5.5.7.1.3';
    const PKIX_QCSYNTAX_V1        = '1.3.6.1.5.5.7.11.1';
    const PKIX_QCSYNTAX_V2        = '1.3.6.1.5.5.7.11.2';
    const ecPublicKey             = '1.2.840.10045.2.1';
    const rsaEncryption           = '1.2.840.113549.1.1.1';
    const RSASSA_PSS              = '1.2.840.113549.1.1.10';
    const emailAddress            = '1.2.840.113549.1.9.1';
    const QcCompliance            = '0.4.0.1862.1.1';
    const QcLimitValue            = '0.4.0.1862.1.2';
    const QcRetentionPeriod       = '0.4.0.1862.1.3';
    const QcSSCD                  = '0.4.0.1862.1.4';
    const QcPDS                   = '0.4.0.1862.1.5';
    const QcType                  = '0.4.0.1862.1.6';
    const esign                   = '0.4.0.1862.1.6.1';
    const eseal                   = '0.4.0.1862.1.6.2';
    const web                     = '0.4.0.1862.1.6.3';
    const RoleOfPsp               = '0.4.0.19495.1';
    const PSP_AS                  = '0.4.0.19495.1.1';
    const PSP_PI                  = '0.4.0.19495.1.2';
    const PSP_AI                  = '0.4.0.19495.1.3';
    const PSP_IC                  = '0.4.0.19495.1.4';
    const PSD2                    = '0.4.0.19495.2';
    const qcpWebPSD2              = '0.4.0.19495.3.1';
    const crlReason               = '2.5.29.21';
    const crlInvalidityDate       = '2.5.29.24';
    const JurisdictionL           = '1.3.6.1.4.1.311.60.2.1.1';
    const JurisdictionST          = '1.3.6.1.4.1.311.60.2.1.2';
    const JurisdictionC           = '1.3.6.1.4.1.311.60.2.1.3';
    const PreCertPoison           = '1.3.6.1.4.1.11129.2.4.3';
    const BasicConstraints        = '2.5.29.19';
    const KeyUsage                = '2.5.29.15';
    const ExtendedKeyUsage        = '2.5.29.37';
    const SubjectKeyIdentifier    = '2.5.29.14';
    const SubjectAltName          = '2.5.29.17';
    const CRLDistributionPoints   = '2.5.29.31';
    const certificatePolicies     = '2.5.29.32';
    const AuthorityKeyIdentifier  = '2.5.29.35';
    const policyConstraints       = '2.5.29.36';
    const AuthorityInformationAccess = '1.3.6.1.5.5.7.1.1';
    const ocsp                    = '1.3.6.1.5.5.7.48.1';
    const caIssuers               = '1.3.6.1.5.5.7.48.2';
    const ServerAuth              = '1.3.6.1.5.5.7.3.1';
    const ClientAuth              = '1.3.6.1.5.5.7.3.2';
    const CodeSigning             = '1.3.6.1.5.5.7.3.3';
    const EmailProtection         = '1.3.6.1.5.5.7.3.4';
    const TimeStamping            = '1.3.6.1.5.5.7.3.8';
    const OCSPSigning             = '1.3.6.1.5.5.7.3.9';
    const TSLSigning              = '0.4.0.2231.3.0';
    // https://www.etsi.org/deliver/etsi_ts/102200_102299/102231/03.01.02_60/ts_102231v030102p.pdf$chapter-6.2
    const EVCP                    = '0.4.0.2042.1.4';
    // https://www.etsi.org/deliver/etsi_ts/102200_102299/102231/03.01.02_60/ts_102231v030102p.pdf$chapter-6.2
    const MS_DOCUMENT_SIGNING     = '1.3.6.1.4.1.311.10.3.12';
    // https://support.microsoft.com/en-us/help/287547/object-ids-associated-with-microsoft-cryptography
    const ipsecEndSystem          = '1.3.6.1.5.5.7.3.5';
    const ipsecTunnel             = '1.3.6.1.5.5.7.3.6';
    const ipsecUser               = '1.3.6.1.5.5.7.3.7';
    const EuQCompliance           = '0.4.0.19422.1.1';
    const extended_validation     = '2.23.140.1.1';
    // https://cabforum.org/object-registry/
    const organization_validation = '2.23.140.1.2.2';
    // https://cabforum.org/object-registry/
    const commonName              = '2.5.4.3';
    const surname                 = '2.5.4.4';
    const serialNumber            = '2.5.4.5';
    const countryName             = '2.5.4.6';
    const localityName            = '2.5.4.7';
    const stateOrProvinceName     = '2.5.4.8';
    const streetAddress           = '2.5.4.9';
    const organizationName        = '2.5.4.10';
    const organizationalUnitName  = '2.5.4.11';
    const title                   = '2.5.4.12';
    const businessCategory        = '2.5.4.15';
    const postalAddress           = '2.5.4.16';
    const postalCode              = '2.5.4.17';
    const telephoneNumber         = '2.5.4.20';
    const givenName               = '2.5.4.42';
    const pseudonym               = '2.5.4.65';
    const organizationIdentifier  = '2.5.4.97';
    // https://www.itu.int/rec/dologin.asp?lang=e&id=T-REC-X.520-201210-S!Cor3!PDF-E&type=items
    const identrusOCSP            = '1.2.840.114021.4.1';
    // https://docs.oracle.com/cd/E19957-01/816-6292-10/com/iplanet/trustbase/initiator/dsms/CSCEngine.html
    const nameDistinguisher       = '0.2.262.1.10.7.20';
    // https://docs.oracle.com/cd/E19957-01/816-6292-10/com/iplanet/trustbase/initiator/dsms/CSCEngine.html
    const domainComponent         = '0.9.2342.19200300.100.1.25';
    // https://docs.oracle.com/cd/E19957-01/816-6292-10/com/iplanet/trustbase/initiator/dsms/CSCEngine.html
    const msSmartCardUPN          = '1.3.6.1.4.1.311.20.2.3';
    // https://tools.ietf.org/html/rfc3279#section-3
    const sha1                    = '1.3.14.3.2.26';
    // https://tools.ietf.org/html/rfc3279#section-3
    const sha1WithRSAEncryption   = '1.2.840.113549.1.1.5';
    // https://tools.ietf.org/html/rfc4055#section-5
    const sha256WithRSAEncryption = '1.2.840.113549.1.1.11';
    // https://tools.ietf.org/html/rfc4055#section-5
    const sha384WithRSAEncryption = '1.2.840.113549.1.1.12';
    // https://tools.ietf.org/html/rfc4055#section-5
    const sha512WithRSAEncryption = '1.2.840.113549.1.1.13';
    // https://tools.ietf.org/html/rfc6960#section-4.4.1
    const ocspNonce               = '1.3.6.1.5.5.7.48.1.2';

    public static function getName($oidString)
    {
        // return 'blah';
        // throw new \Exception("Error Processing Request", 1);

        switch ($oidString) {
          case self::qcStatements:
              $oidName = 'qcStatements';
              break;
          case self::PKIX_QCSYNTAX_V1:
              $oidName = 'id-qcs-pkixQCSyntax-v1';
              break;
          case self::PKIX_QCSYNTAX_V2:
              $oidName = 'id-qcs-pkixQCSyntax-v2';
              break;
          case self::ecPublicKey:
              $oidName = 'ecPublicKey';
              break;
          case self::rsaEncryption:
              $oidName = 'rsaEncryption';
              break;
          case self::RSASSA_PSS:
              $oidName = 'RSASSA-PSS';
              break;
          case self::emailAddress:
              $oidName = 'emailAddress';
              break;
          case self::QcCompliance:
              $oidName = 'QcCompliance';
              break;
          case self::QcLimitValue:
            $oidName = 'QcLimitValue';
            break;
          case self::QcRetentionPeriod:
            $oidName = 'QcRetentionPeriod';
            break;
          case self::QcSSCD:
            $oidName = 'QcSSCD';
            break;
          case self::QcPDS:
            $oidName = 'QcPDS';
            break;
          case self::QcType:
            $oidName = 'QcType';
            break;
          case self::esign:
            $oidName = 'esign';
            break;
          case self::eseal:
            $oidName = 'eseal';
            break;
          case self::web:
            $oidName = 'web';
            break;
          case self::RoleOfPsp:
            $oidName = 'RoleOfPsp';
            break;
          case self::PSP_AS:
            $oidName = 'PSP_AS';
            break;
          case self::PSP_PI:
            $oidName = 'PSP_PI';
            break;
          case self::PSP_AI:
            $oidName = 'PSP_AI';
            break;
          case self::PSP_IC:
            $oidName = 'PSP_IC';
            break;
          case self::PSD2:
            $oidName = 'PSD2';
            break;
          case self::qcpWebPSD2:
            $oidName = 'qcpWebPSD2';
            break;
          case self::BasicConstraints:
            $oidName = 'basicConstraints';
            break;
          case self::extended_validation:
            $oidName = 'extended_validation';
            break;
          case self::organization_validation:
            $oidName = 'organization_validation';
            break;
          case self::KeyUsage:
            $oidName = 'keyUsage';
            break;
          case self::ExtendedKeyUsage:
            $oidName = 'extKeyUsage';
            break;
          case self::CRLDistributionPoints:
            $oidName = 'crlDistributionPoints';
            break;
          case self::JurisdictionST:
            $oidName = 'JurisdictionST';
            break;
          case self::JurisdictionC:
            $oidName = 'JurisdictionC';
            break;
          case self::JurisdictionL:
            $oidName = 'JurisdictionL';
            break;
          case self::PreCertPoison:
            $oidName = 'preCertPoison';
            break;
          case self::crlReason:
            $oidName = 'crlReason';
            break;
          case self::crlInvalidityDate:
            $oidName = 'crlInvalidityDate';
            break;
          case self::certificatePolicies:
            $oidName = 'certificatePolicies';
            break;
          case self::AuthorityKeyIdentifier:
            $oidName = 'authorityKeyIdentifier';
            break;
          case self::policyConstraints:
            $oidName = 'policyConstraints';
            break;
          case self::SubjectKeyIdentifier:
            $oidName = 'subjectKeyIdentifier';
            break;
          case self::SubjectAltName:
            $oidName = 'subjectAltName';
            break;
          case self::ServerAuth:
            $oidName = 'serverAuth';
            break;
          case self::AuthorityInformationAccess:
            $oidName = 'authorityInfoAccess';
            break;
          case self::caIssuers:
            $oidName = 'caIssuers';
            break;
          case self::ocsp:
            $oidName = 'ocsp';
            break;
          case self::ClientAuth:
            $oidName = 'clientAuth';
            break;
          case self::CodeSigning:
            $oidName = 'codeSigning';
            break;
          case self::EmailProtection:
            $oidName = 'emailProtection';
            break;
          case self::TimeStamping:
            $oidName = 'timeStamping';
            break;
          case self::OCSPSigning:
            $oidName = 'OCSPSigning';
            break;
          case self::TSLSigning:
            $oidName = 'tslSigning';
            break;
          case self::EVCP:
            $oidName = 'EVCP';
            break;
          case self::MS_DOCUMENT_SIGNING:
            $oidName = 'MS_DOCUMENT_SIGNING';
            break;
          case self::EuQCompliance:
            $oidName = 'etsi-tsts-EuQCompliance';
            break;
          case self::commonName:
            $oidName = 'commonName';
            break;
          case self::surname:
            $oidName = 'surname';
            break;
          case self::givenName:
            $oidName = 'givenName';
            break;
          case self::pseudonym:
            $oidName = 'pseudonym';
            break;
          case self::serialNumber:
            $oidName = 'serialNumber';
            break;
          case self::countryName:
            $oidName = 'countryName';
            break;
          case self::localityName:
            $oidName = 'localityName';
            break;
          case self::stateOrProvinceName:
            $oidName = 'stateOrProvinceName';
            break;
          case self::organizationName:
            $oidName = 'organizationName';
            break;
          case self::organizationalUnitName:
            $oidName = 'organizationalUnitName';
            break;
          case self::title:
            $oidName = 'title';
            break;
          case self::businessCategory:
            $oidName = 'businessCategory';
            break;
          case self::postalAddress:
            $oidName = 'postalAddress';
            break;
          case self::telephoneNumber:
            $oidName = 'telephoneNumber';
            break;
          case self::streetAddress:
            $oidName = 'streetAddress';
            break;
          case self::postalCode:
            $oidName = 'postalCode';
            break;
          case self::organizationIdentifier:
            $oidName = 'organizationIdentifier';
            break;
          case self::identrusOCSP:
            $oidName = 'identrusOCSP';
            break;
          case self::nameDistinguisher:
            $oidName = 'nameDistinguisher';
            break;
          case self::domainComponent:
            $oidName = 'domainComponent';
            break;
          case self::msSmartCardUPN:
            $oidName = 'msSmartCardUPN';
            break;
          case self::sha1:
            $oidName = 'sha-1';
            break;
          case self::sha1WithRSAEncryption:
            $oidName = 'sha1WithRSAEncryption';
            break;
          case self::sha256WithRSAEncryption:
            $oidName = 'sha256WithRSAEncryption';
            break;
          case self::sha384WithRSAEncryption:
            $oidName = 'sha384WithRSAEncryption';
            break;
          case self::sha512WithRSAEncryption:
            $oidName = 'sha512WithRSAEncryption';
            break;
          case self::ocspNonce:
            $oidName = 'ocspNonce';
            break;
          default:
            $oidName = 'unknown';
            break;
          }
        return $oidName;
        // return "$oidString ($oidName)";
    }

    public static function getShortName($name)
    {
        switch ($name) {
          case 'countryName':
            return 'C';
            break;
          case 'organizationalUnitName':
            return 'OU';
            break;
          case 'stateOrProvinceName':
            return 'ST';
            break;
          case 'organizationName':
            return 'O';
            break;
          case 'commonName':
            return 'CN';
            break;
          case 'givenName':
            return 'GN';
            break;
          case 'organizationIdentifier':
            return '2.5.4.97';
            break;
          case 'localityName':
            return 'L';
            break;
          case 'surname':
            return 'SN';
            break;
          case 'domainComponent':
            return 'DC';
            break;

          default:
            return $name;
            break;
        }
    }

    public static function getURI($oid)
    {
        switch ($oid) {
          case self::TSLSigning:
            return 'https://www.etsi.org/deliver/etsi_ts/102200_102299/102231/03.01.02_60/ts_102231v030102p.pdf$chapter-6.2';
            break;
          case self::MS_DOCUMENT_SIGNING:
            return 'https://support.microsoft.com/en-us/help/287547/object-ids-associated-with-microsoft-cryptography';
            break;

          default:
            if (substr($oid, 0, 15) == '1.3.6.1.5.5.7.3') {
                return 'https://tools.ietf.org/html/rfc5280#section-4.2.1.12';
            } else {
                return null;
            }
            break;
        }
    }

    public static function getOID($name)
    {
        switch ($name) {
          case 'sha1':
          case 'sha-1':
            return '1.3.14.3.2.26';
            break;
          case 'ocspNonce':
            return '1.3.6.1.5.5.7.48.1.2';
            break;
          default:
            return 'unknown';
            break;
        }
    }
}
