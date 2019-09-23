<?php

namespace eIDASCertificate;

/**
 *
 */
class OID
{
    const qcStatements            = '1.3.6.1.5.5.7.1.3';
    const PKIX_QCSYNTAX_V2        = '1.3.6.1.5.5.7.11.2';
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
    const crlReason               = '2.5.29.21';
    const crlInvalidityDate       = '2.5.29.24';
    const PreCertPoison           = '1.3.6.1.4.1.11129.2.4.3';
    const BasicConstraints        = '2.5.29.19';
    const KeyUsage                = '2.5.29.15';
    const ExtendedKeyUsage        = '2.5.29.37';
    const SubjectKeyIdentifier    = '2.5.29.14';
    const AuthorityKeyIdentifier  = '2.5.29.35';
    const CRLDistributionPoints   = '2.5.29.31';
    const ServerAuth              = '1.3.6.1.5.5.7.3.1';
    const ClientAuth              = '1.3.6.1.5.5.7.3.2';
    const CodeSigning             = '1.3.6.1.5.5.7.3.3';
    const EmailProtection         = '1.3.6.1.5.5.7.3.4';
    const TimeStamping            = '1.3.6.1.5.5.7.3.8';
    const OCSPSigning             = '1.3.6.1.5.5.7.3.9';
    const TSLSigning              = '0.4.0.2231.3.0';
    // https://www.etsi.org/deliver/etsi_ts/102200_102299/102231/03.01.02_60/ts_102231v030102p.pdf$chapter-6.2
    const MS_DOCUMENT_SIGNING     = '1.3.6.1.4.1.311.10.3.12';
    // https://support.microsoft.com/en-us/help/287547/object-ids-associated-with-microsoft-cryptography
    const ipsecEndSystem          = '1.3.6.1.5.5.7.3.5';
    const ipsecTunnel             = '1.3.6.1.5.5.7.3.6';
    const ipsecUser               = '1.3.6.1.5.5.7.3.7';

    public static function getName($oidString)
    {
        // return 'blah';
        // throw new \Exception("Error Processing Request", 1);

        switch ($oidString) {
          case self::qcStatements:
              $oidName = 'qcStatements';
              break;
          case self::PKIX_QCSYNTAX_V2:
              $oidName = 'id-qcs-pkixQCSyntax-v2';
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
          case self::BasicConstraints:
            $oidName = 'basicConstraints';
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
          case self::PreCertPoison:
            $oidName = 'preCertPoison';
            break;
          case self::crlReason:
            $oidName = 'crlReason';
            break;
          case self::crlInvalidityDate:
            $oidName = 'crlInvalidityDate';
            break;
          case self::AuthorityKeyIdentifier:
            $oidName = 'authorityKeyIdentifier';
            break;
          case self::SubjectKeyIdentifier:
            $oidName = 'subjectKeyIdentifier';
            break;
          case self::ServerAuth:
            $oidName = 'serverAuth';
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
          case self::MS_DOCUMENT_SIGNING:
            $oidName = 'MS_DOCUMENT_SIGNING';
            break;
          // case self::ipsecEndSystem:
          //   $oidName = 'ipsecEndSystem';
          //   break;
          // case self::ipsecTunnel:
          //   $oidName = 'ipsecTunnel';
          //   break;
          // case self::ipsecUser:
          //   $oidName = 'ipsecUser';
          //   break;
          default:
            $oidName = 'unknown';
            break;
          }
        return $oidName;
        // return "$oidString ($oidName)";
    }
}
