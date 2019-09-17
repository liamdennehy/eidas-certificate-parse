<?php

namespace eIDASCertificate\DigitalIdentity;

use eIDASCertificate\Certificate\X509Certificate;

/**
 *
 */
abstract class DigitalId
{
    public static function parse($digitalId)
    {
        $childNodes = $digitalId->xpath('*');
        $identifier = $childNodes[0];
        $type = $identifier->getname();
        switch ($type) {
        case 'X509Certificate':
            $value = new X509Certificate($identifier);
            // $value = openssl_x509_read(
            //     Certificate\X509Certificate::base64ToPEM((string)$identifier)
            // );
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
        return [$type => $value];
    }
}
