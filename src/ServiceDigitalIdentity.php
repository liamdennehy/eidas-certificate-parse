<?php

namespace eIDASCertificate;

use phpseclib\File\X509;

/**
 *
 */
class ServiceDigitalIdentity
{
    private $x509Certificate;
    private $x509SubjectName;
    private $x509SKI;
    private $otherId;

    public function __construct($serviceDigitalIdentity)
    {
        foreach ($serviceDigitalIdentity->DigitalId->children() as $identifier) {
            $IDType = $identifier->getName();
            switch ($IDType) {
                case 'X509Certificate':
                    if ( $this->x509Certificate ) {
                        throw new \Exception("Duplicate Certificate", 1);
                    }
                    $this->x509Certificate = openssl_x509_read(
                        $this->string2pem(
                            (string)$serviceDigitalIdentity->DigitalId->X509Certificate
                            )
                    );
                    break;
                case 'X509SKI':
                    $this->x509SKI =
                        (string)$serviceDigitalIdentity->DigitalId->X509SKI;
                    break;
                case 'X509SubjectName':
                    $this->x509SubjectName =
                        (string)$serviceDigitalIdentity->DigitalId->X509SubjectName;
                    break;
                case 'Other':
                    $this->otherId = (string)$serviceDigitalIdentity->DigitalId->Other;
                    break;
                default:
                    throw new ParseException("Unknown ServiceDigitalIdentity Type $IDType", 1);
                    break;
            }
        };
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
            return base64_encode(hash($algo,$pubkeyn,true));
        } else {
            return $this->x509SKI;
        }
    }

    public function getX509SubjectName()
    {
        return $this->x509SubjectName;
    }

}
