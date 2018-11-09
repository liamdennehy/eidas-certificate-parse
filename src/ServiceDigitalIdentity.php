<?php

namespace eIDASCertificate;

/**
 *
 */
class ServiceDigitalIdentity
{
    private $x509Certificates = [];

    public function __construct($serviceDigitalIdentities)
    {
        foreach ($serviceDigitalIdentities->xpath('*') as $serviceDigitalIdentity) {
            $this->x509Certificates[] = openssl_x509_read(
                $this->string2pem(
                    (string)$serviceDigitalIdentity->DigitalId->X509Certificate
                )
            );
        };
    }

    private function string2pem($certificateString)
    {
        return "-----BEGIN CERTIFICATE-----\n" .
      chunk_split($certificateString, 64, "\n") .
      "-----END CERTIFICATE-----\n";
    }

    public function getX509Certificates()
    {
        return $this->x509Certificates;
    }

    public function getX509Thumbprints()
    {
        $thumbprints = [];
        foreach ($this->x509Certificates as $x509Certificate) {
            $thumbprints[] = openssl_x509_fingerprint($x509Certificate);
        };
        return $thumbprints;
    }
}
