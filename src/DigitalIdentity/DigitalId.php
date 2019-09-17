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
            return new X509Certificate((string)$identifier);
            break;
        case 'X509SKI':
            return new X509SKI((string)$identifier);
            break;
        case 'X509SubjectName':
            return new X509SubjectName((string)$identifier);
            break;
        case 'Other':
            return new OtherDigitalId((string)$identifier);
            break;
        default:
            throw new ParseException("Unknown ServiceDigitalIdentity Type $IDType", 1);
            break;
        };
    }
}
