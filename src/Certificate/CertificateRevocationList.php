<?php

namespace eIDASCertificate\Certificate;

use ASN1\Type\UnspecifiedType;
use eIDASCertificate\Certificate\CRLException;
use eIDASCertificate\OID;

/**
 *
 */
class CertificateRevocationList
{
    private $binary;
    private $revokedCertificates;

    public function __construct($crlDER)
    {
        $this->revokedCertificates = [];
        $crl = UnspecifiedType::fromDER($crlDER)->asSequence();
        $tbsCertList = $crl->at(0)->asSequence();
        $signatureAlgorithm = $crl->at(1)->asSequence();
        $signatureValue = $crl->at(2)->asBitString()->string();
        $version = $tbsCertList->at(0)->asInteger()->intNumber();
        if ($version != 1) {
            throw new CRLException("Only v2 CRLs are supported", 1);
        }
        $signature = $tbsCertList->at(1)->asSequence();
        $issuer = $tbsCertList->at(2)->asSequence();
        $thisUpdate = $tbsCertList->at(3)->asUTCTime()->dateTime();
        $nextUpdate = $tbsCertList->at(4)->asUTCTime()->dateTime();
        $crlEntries = $tbsCertList->at(5)->asSequence();
        if ($tbsCertList->has(6)) {
            $crlExtensions = $tbsCertList->at(6)->asTagged();
            // TODO: process CRL extensions
        }
        foreach ($crlEntries->elements() as $crlEntry) {
            $certSerial = $crlEntry->asSequence()->at(0)->asInteger()->number();
            $certRevokedDateTime =
                $crlEntry->at(1)->asUTCTime()->dateTime();
            $this->revokedCertificates[$certSerial]['time'] = $certRevokedDateTime;
            if ($crlEntry->has(2)) {
                $crlEntryExtensions = $crlEntry->at(2)->asSequence()->elements();
                foreach ($crlEntryExtensions as $crlEntryExtension) {
                    $crlEntryExtension = $crlEntryExtension->asSequence();
                    $crlEntryExtensionOID = $crlEntryExtension->at(0)->asObjectIdentifier()->oid();
                    $crlEntryExtensionName = OID::getName($crlEntryExtensionOID);
                    $crlEntryExtensionDER = $crlEntryExtension->at(1)->asOctetString()->string();
                    switch ($crlEntryExtensionName) {
                  case 'crlReason':
                    $reasonEnumerated = UnspecifiedType::fromDER($crlEntryExtensionDER)->asEnumerated()->number();
                    $reasonName = self::getCRLReasonName($reasonEnumerated);
                    if ($reasonName == 'unknown') {
                        throw new CRLException("Unrecognised CRL Entry reason number $reasonEnumerated ($reasonName)", 1);
                    }
                    $this->revokedCertificates[$certSerial]['reason'] = $reasonName;
                    break;
                  case 'crlInvalidityDate':
                    $crlEntryInvalidityDate = UnspecifiedType::fromDER($crlEntryExtensionDER)->asGeneralizedTime()->dateTime();
                    $this->revokedCertificates[$certSerial]['invalidityDate'] = $crlEntryInvalidityDate;
                    break;
                  default:
                    throw new CRLException("Unknown CRL entry extension OID $crlEntryExtensionOID ($crlEntryExtensionName) for serial $certSerial", 1);

                  break;
                }
                }
            }
        }
        $this->binary = $crlDER;
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

    public function isRevoked($certSerial)
    {
        if (array_key_exists($certSerial, $this->revokedCertificates)) {
            $revoked['serial'] = $certSerial;
            $revoked['time'] = $this->revokedCertificates[$certSerial]['time'];
            if (array_key_exists('reason', $this->revokedCertificates[$certSerial])) {
                $revoked['reason'] = $this->revokedCertificates[$certSerial]['reason'];
            }
            if (array_key_exists('invalidityDate', $this->revokedCertificates[$certSerial])) {
                $revoked['invalidityDate'] = $this->revokedCertificates[$certSerial]['invalidityDate'];
            }
            return $revoked;
        } else {
            return false;
        }
    }

    public function getCount()
    {
        return sizeof($this->revokedCertificates);
    }

    public function getRevokedSerials()
    {
        return array_keys($this->revokedCertificates);
    }

    public static function getCRLReasonName($enumeratedNumber)
    {
        switch ($enumeratedNumber) {
        case 0:
          return 'unspecified';
          break;
        case 1:
          return 'keyCompromise';
          break;
        case 2:
          return 'cACompromise';
          break;
        case 3:
          return 'affiliationChanged';
          break;
        case 4:
          return 'superseded';
          break;
        case 5:
          return 'cessationOfOperation';
          break;
        case 6:
          return 'certificateHold';
          break;
        case 8:
          return 'removeFromCRL';
          break;
        case 9:
          return 'privilegeWithdrawn';
          break;
        case 10:
          return 'aACompromise';
          break;
        default:
          return 'unknown';
          break;
        }
    }
}
