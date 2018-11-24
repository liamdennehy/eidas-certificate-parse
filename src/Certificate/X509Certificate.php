<?php

namespace eIDASCertificate;

/**
 *
 */
class X509Certificate
{
    public static function emit($candidate)
    {
        if (is_null($candidate)) {
            return false;
        };
        try {
            if (substr($candidate, 0, 3) == 'MII') {
                $candidate = X509Certificate::base64ToPEM($candidate);
            };
        } catch (\Exception $e) {
            // No-op, probably a X.509 Resource
        };
        $certificate = openssl_x509_read($candidate);
        if ($certificate) {
            return $certificate;
        } else {
            throw new CertificateException("Cannot recognise certificate", 1);
        }
    }

    public static function base64ToPEM($certificateString)
    {
        // Handle line-wrapped presentations of base64
        $certificateString = base64_encode(
            base64_decode($certificateString)
        );
        return "-----BEGIN CERTIFICATE-----\n" .
        chunk_split($certificateString, 64, "\n") .
        "-----END CERTIFICATE-----\n";
    }

    public static function getDN($cert)
    {
        return openssl_x509_parse($cert)['name'];
    }
}
