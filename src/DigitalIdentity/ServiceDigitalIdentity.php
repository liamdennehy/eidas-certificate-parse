<?php

namespace eIDASCertificate\DigitalIdentity;

/**
 *
 */
class ServiceDigitalIdentity
{
    private $digitalIds = [];

    /**
     * [__construct description]
     * @param SimpleXMLElement $serviceDigitalIdentity [description]
     * @throws TSPException
     */
    public function __construct($serviceDigitalIdentity)
    {
        $this->digitalIds = [];
        foreach ($serviceDigitalIdentity->children() as $digitalId) {
            $newDigitalId = DigitalId::parse($digitalId);
            foreach ($newDigitalId as $type => $value) {
                $this->digitalIds[$type][] = $value;
            };
        };
    }

    /**
     * [getX509Certificates description]
     * @return array [description]
     */
    public function getX509Certificates()
    {
        $x509Certificates = [];
        foreach ($this->digitalIds as $type => $digitalId) {
            if ($type == 'X509Certificate') {
                foreach ($digitalId as $certificate) {
                    $x509Certificates[] = $certificate;
                }
            }
        };
        return $x509Certificates;
    }

    /**
     * [getDigitalIds description]
     * @return array [description]
     */
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

    /**
     * [getX509SKI description]
     * @param  string $algo [description]
     * @return [type]       [description]
     */
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
