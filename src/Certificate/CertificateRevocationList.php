<?php

namespace eIDASCertificate\Certificate;

use ASN1\Type\UnspecifiedType;
use eIDASCertificate\Certificate\CRLException;

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
        $revokedCertificates = $tbsCertList->at(5)->asSequence();
        $crlExtensions = $tbsCertList->at(6)->asTagged();
        foreach ($revokedCertificates->elements() as $revokedCertificate) {
            $certSerial = $revokedCertificate->at(0)->asInteger()->number();
            $certRevokedDateTime = $revokedCertificate->at(1)->asUTCTime()->dateTime();
            $this->revokedCertificates[$certSerial]['time'] = $certRevokedDateTime;
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
            $revoked['time'] = $this->revokedCertificates[$certSerial]['time'];
            if (array_key_exists('reason', $this->revokedCertificates[$certSerial])) {
                $revoked['reason'] = $this->revokedCertificates[$certSerial]['reason'];
            }
            return revoked;
        } else {
            return false;
        }
    }

    public function getCount()
    {
        return sizeof($this->revokedCertificates);
    }
}
