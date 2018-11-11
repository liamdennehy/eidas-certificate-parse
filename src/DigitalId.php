<?php

namespace eIDASCertificate;

/**
 *
 */
abstract class DigitalId
{
    public static function parse($digitalId)
    {
        $childNodes = $digitalId->xpath('*');
        $identifier = $childNodes[0];
        switch ($identifier->getname()) {
        case 'X509Certificate':
            $value = openssl_x509_read(
                SELF::string2pem((string)$identifier)
            );
            break;
        case 'X509SKI':
            $value = (string)$identifier;
            break;
        case 'X509SubjectName':
            $value = (string)$identifier;
            break;
        case 'Other':
            $value = (string)$identifier;
            break;
        default:
            throw new ParseException("Unknown ServiceDigitalIdentity Type $IDType", 1);
            break;
        };
        return [$identifier->getname() => $value];
    }

    public static function string2pem($certificateString)
    {
        // Handle line-wrapped presentations of base64
        $certificateString = base64_encode(
            base64_decode($certificateString)
        );
        return "-----BEGIN CERTIFICATE-----\n" .
        chunk_split($certificateString, 64, "\n") .
        "-----END CERTIFICATE-----\n";
    }
}
