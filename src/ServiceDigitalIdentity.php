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
        foreach ($serviceDigitalIdentity->DigitalId as $digitalId) {
            $this->digitalIds[] = new DigitalId($digitalId);
        };
    }

    public function getX509Certificates()
    {
        $x509Certificates = [];
        foreach ($this->digitalIds as $digitalId) {
            $x509Certificates[] = $digitalId->getX509Certificate();
        };
        return $x509Certificates;
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
