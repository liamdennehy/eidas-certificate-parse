<?php

namespace eIDASCertificate;

/**
 *
 */
class DigitalId
{
    private $type;
    private $value;

    public function __construct($digitalId)
    {
        $childNodes = $digitalId->xpath('*');
        $identifier = $childNodes[0];
        $this->type = $identifier->getname();
        switch ($this->type) {
        case 'X509Certificate':
            $this->value = openssl_x509_read(
                $this->string2pem((string)$identifier)
            );
            break;
        case 'X509SKI':
            $this->value = (string)$identifier;
            break;
        case 'X509SubjectName':
            $this->value = (string)$identifier;
            break;
        case 'Other':
            $this->value = (string)$identifier;
            break;
        default:
            throw new ParseException("Unknown ServiceDigitalIdentity Type $IDType", 1);
            break;
        }
    }

    private function string2pem($certificateString)
    {
        // Handle line-wrapped presentations of base64
        $certificateString = base64_encode(
            base64_decode($certificateString)
        );
        return "-----BEGIN CERTIFICATE-----\n" .
        chunk_split($certificateString, 64, "\n") .
        "-----END CERTIFICATE-----\n";
    }

    public function getType()
    {
        return $this->type;
    }

    public function getValue()
    {
        return $this->value;
    }
}
