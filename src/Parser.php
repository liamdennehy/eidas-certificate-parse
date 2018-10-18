<?php

namespace PSD2Certificate;

use phpseclib\File\X509;
use phpseclib\File\ASN1;

/**
 *
 */
class Parser
{
    private $cert;
    private $qcStatements;
    public function __construct($pem)
    {
        $x509 = new X509();
        $this->cert = $x509->loadX509($pem);
        if (! array_key_exists('tbsCertificate', $this->cert)) {
            throw new CertificateException('Data does not appear to hold a X.509 certificate');
        } elseif (! array_key_exists('version', $this->cert['tbsCertificate'])) {
            throw new CertificateException('Cannot determine certificate version');
        } elseif ($this->cert['tbsCertificate']['version'] != "v3") {
            throw new CertificateException('Certificate is not X.509 v3');
        } elseif (! array_key_exists('extensions', $this->cert['tbsCertificate'])) {
            throw new CertificateException('Cannot find the extension attributes');
        } elseif (is_null(array_search('1.3.6.1.5.5.7.1.3', $this->cert))) {
            throw new CertificateException('This does not appear to be a Qualified Certificate');
        };
        $qcStatementIndex = array_search('1.3.6.1.5.5.7.1.3', $this->cert['tbsCertificate']['extensions']) + 1;
        $this->qcStatements =
            $this->cert['tbsCertificate']['extensions'][$qcStatementIndex];
    }

    public function DumpCert()
    {
        return $this->cert['tbsCertificate'];
    }

    public function dumpExtensions()
    {
        return $this->cert['tbsCertificate']['extensions'];
    }

    public function dumpQCStatements()
    {
        $asn1 = new ASN1();
        $extensions = $this->cert['tbsCertificate']['extensions'];
        $decoded = $asn1->decodeBER(base64_decode($extensions[9]['extnValue']))[0]['content'];
        return
        [
          $decoded[0]['content'],
          $decoded[1]['content'],
          $decoded[2]['content'],
          $decoded[3]['content'],
          $decoded[4]['content'],
          ];
    }
}
