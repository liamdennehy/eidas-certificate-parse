<?php

namespace eIDASCertificate;

use phpseclib\File\X509;

/**
 *
 */
class ServiceDigitalIdentity
{
    private $digitalIds = [];

    public function __construct($serviceDigitalIdentity)
    {
        foreach ($serviceDigitalIdentity->children() as $digitalId) {
            $this->digitalIds[] = new DigitalId($digitalId);
        };
    }

    public function getX509Certificates()
    {
        $x509Certificates = [];
        foreach ($this->digitalIds as $digitalId) {
            if ($digitalId->getType() == 'X509Certificate') {
                $x509Certificates[] = $digitalId->getValue();
            }
        };
        return $x509Certificates;
    }

    public function getDigitalIds()
    {
        return $this->digitalIds;
    }

    public function getX509Certificate()
    {
        return $this->x509Certificate;
    }

    public function getX509Thumbprint()
    {
        return openssl_x509_fingerprint($this->x509Certificate);
    }

    public function getX509SKI($algo = 'sha256')
    {
        if (! $this->x509SKI) {
            $pubkey = openssl_pkey_get_public($this->x509Certificate);
            $pubkeyn = openssl_pkey_get_details($pubkey)['rsa']['n'];
            return base64_encode(hash($algo, $pubkeyn, true));
        } else {
            return $this->x509SKI;
        }
    }

    public function getX509SubjectName()
    {
        return $this->x509SubjectName;
    }

}
