<?php

namespace eIDASCertificate\Certificate;

use eIDASCertificate\QCStatements;
/**
 *
 */
class X509Certificate
{
    private $crtResource;
    private $parsed;

    public function __construct($candidate)
    {
      $this->crtResource = X509Certificate::emit($candidate);
    }

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
            // No-op, probably already X.509 Resource
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

    public static function getHash($cert, $algo = 'sha256')
    {
        return openssl_x509_fingerprint($cert, $algo);
    }

    public static function parse($crt)
    {
      $crtParsed = openssl_x509_parse($crt);
      return $crtParsed;
    }

    public function getParsed()
    {
      if (empty($this->parsed)) {
        $this->parsed = X509Certificate::parse($this->crtResource);
      }
      return $this->parsed;
    }

    public function hasExtensions()
    {
      return array_key_exists('extensions',X509Certificate::parse($this->crtResource));
    }

    public function hasQCStatements()
    {
      if ($this->hasExtensions()) {
        return array_key_exists('qcStatements',X509Certificate::parse($this->crtResource)['extensions']);
      }
      // return new qcStatements($this->crtResource);
    }

    public function getQCStatements()
    {
      if ($this->hasQCStatements()) {
        return new QCStatements($this->getParsed()['extensions']['qcStatements']);
      }
    }
}
