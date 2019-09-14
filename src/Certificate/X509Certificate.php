<?php

namespace eIDASCertificate\Certificate;

use eIDASCertificate\QCStatements;
use FG\ASN1\ASNObject;

/**
 *
 */
class X509Certificate
{
    private $crtResource;
    private $crtBinary;
    private $parsed;

    public function __construct($candidate)
    {
        $this->crtResource = X509Certificate::emit($candidate);
        openssl_x509_export($this->crtResource, $crtPEM);
        $crtPEM = explode("\n", $crtPEM);
        unset($crtPEM[sizeof($crtPEM)-1]);
        unset($crtPEM[0]);
        $this->crtBinary = base64_decode(implode("", $crtPEM));
        $crtASN1 = ASNObject::fromBinary($this->crtBinary)[0];
        $crtVersion = $crtASN1[0]->getContent()[0]->getContent() + 1;
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
        return array_key_exists('extensions', $this->getParsed());
    }

    public function hasQCStatements()
    {
        if ($this->hasExtensions()) {
            return array_key_exists('qcStatements', $this->getParsed()['extensions']);
        }
    }

    public function getQCStatements()
    {
        if ($this->hasQCStatements()) {
            if (empty($this->qcStatements)) {
                $qcStatements = new QCStatements(
                    $this->getParsed()['extensions']['qcStatements']
                );
                $this->qcStatements = $qcStatements->getStatements();
            }
            return $this->qcStatements;
        }
    }

    public function toDER()
    {
        return $this->crtBinary;
    }

    public function getExtensions()
    {
        $crtObject=ASNObject::fromBinary($this->crtBinary);
        $tbsCertificate = $crtObject[0];
        $extensions = $tbsCertificate[7]->getContent()[0]->getContent();
        return $extensions;
    }
}
