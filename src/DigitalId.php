<?php

namespace eIDASCertificate;

/**
 *
 */
class DigitalId
{
    private $x509Certificate;
    private $x509SubjectName;
    private $x509SKI;
    private $otherId;

    public function __construct($digitalId)
    {
        foreach ($digitalId->children() as $identifier) {
            switch ($identifier->getname()) {
            case 'X509Certificate':
                if ($this->x509Certificate) {
                    throw new \Exception("Duplicate Certificate", 1);
                }
                $this->x509Certificate = openssl_x509_read(
                    $this->string2pem(
                        (string)$identifier
                        )
                );
                break;
            case 'X509SKI':
                $this->x509SKI =
                    (string)$identifier;
                break;
            case 'X509SubjectName':
                $this->x509SubjectName =
                    (string)$identifier;
                break;
            case 'Other':
                $this->otherId = (string)$identifier;
                break;
            default:
                throw new ParseException("Unknown ServiceDigitalIdentity Type $IDType", 1);
                break;
        }
        }
    }

    private function string2pem($certificateString)
    {
        return "-----BEGIN CERTIFICATE-----\n" .
      chunk_split($certificateString, 64, "\n") .
      "-----END CERTIFICATE-----\n";
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
