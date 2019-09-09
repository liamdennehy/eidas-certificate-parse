<?php

namespace eIDASCertificate\Signature;

use RobRichards\XMLSecLibs\XMLSecurityDSig;
use RobRichards\XMLSecLibs\XMLSecEnc;
use DOMDocument;
use eIDASCertificate\Certificate;
use eIDASCertificate\CertificateException;
use eIDASCertificate\SignatureException;

/**
 *
 */
class XMLSig
{
    const XMLDSIGNS = 'http://www.w3.org/2000/09/xmldsig#';

    private $doc;
    private $certificates = [];
    private $signedBy;
    private $docname;

    /**
     * [__construct description]
     * @param string $xml          [description]
     * @param array  $certificates [description]
     */
    public function __construct($xml, $certificates, $docName = '')
    {
        $this->doc = new DOMDocument();
        $this->doc->loadXML($xml);
        if (! is_array($certificates)) {
          $certificates = [$certificates];
        }
        foreach ($certificates as $certificate) {
            $signingCertificate = openssl_x509_read($certificate);
            if (! $signingCertificate) {
                throw new CertificateException(
                  "Bad certificate supplied for XML Signature Verification", 1
                );
            } else {
                $this->certificates[] = $signingCertificate;
            };
        };
        $this->docName = $docName;
    }

    public function verifySignature()
    {
        $secDsig = new XMLSecurityDSig();
        $dsig = $secDsig->locateSignature($this->doc);
        if ($dsig === null) {
            throw new SignatureException('Cannot locate signature block');
        }
        $secDsig->canonicalizeSignedInfo();
        $secDsig->idKeys = array('wsu:Id');
        $secDsig->idNS = array(
          'wsu' => 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd'
        );
        $xpath = new \DOMXPath($this->doc);
        $xpath->registerNamespace('secdsig', self::XMLDSIGNS);
        // TODO: Figure out what this signature means
        // This is a hideous kluge as this signature type isn't understood by xmlseclibs
        // As a result it calculates a null-string hash as the digest, and fails validation.
        // Unknown impact on scheme security.
        $query = './/secdsig:Reference[@Type="http://uri.etsi.org/01903#SignedProperties"]';
        $etsirefNodes = $xpath->query($query, $this->doc);
        foreach ($etsirefNodes as $etsirefNode) {
            $etsirefNode->parentNode->removeChild($etsirefNode);
        }
        if (!$secDsig->validateReference()) {
            throw new DigestException(
                'Reference validation failed, might be related to a bad digest (algorithm)'
            );
        }
        $key = $secDsig->locateKey();
        var_dump($key); exit;
        if ($key === null) {
            throw new SignatureException(
                'Could not find signing key in signature block',
                [$this->docName]
            );
        }
        $keyInfo = XMLSecEnc::staticLocateKeyInfo($key, $dsig);
        // Unknown Purpose...
        // if (!$keyInfo->key) {
        //     $key->loadKey($certificate);
        // };
        if ($secDsig->verify($key) === 1) {
            $signedBy = Certificate\X509Certificate::emit(
              $key->getX509Certificate()
            );
            if ($signedBy) {
                $foundThumb = openssl_x509_fingerprint($signedBy, 'sha256');
                $validThumbs = $this->getX509Thumbprints('sha256');
            } else {
                $foundThumb = $key->getX509Thumbprint();
                foreach ($this->getX509Thumbprints('sha1') as $validThumb) {
                    $validThumbs[] = $validThumb;
                }
            };

            if (in_array($foundThumb, $validThumbs)) {
                $this->signedBy = $signedBy;
                return true;
            } else {
                $out['signedBy'] = $foundThumb;
                $out['availableCerts'] = $validThumbs;
                throw new SignatureException(
                    "Unable to match signature to authorised certificate thumbprint",
                    $out
                );
            }
        }
    }

    /**
     * [getX509Thumbprints description]
     * @param  string $algo [description]
     * @return [type]       [description]
     */
    public function getX509Thumbprints($algo = 'sha256')
    {
        $thumbprints = [];
        foreach ($this->certificates as $certificate) {
            $thumbprints[] = openssl_x509_fingerprint($certificate, $algo);
        };
        return $thumbprints;
    }

    public function getX509Certificates()
    {
        $certificates = [];
        foreach ($this->certificates as $certificate) {
            $certificates[
                openssl_x509_fingerprint($certificate, 'sha256')
                ] = $certificate;
        };
        return $certificates;
    }

    public function getSignedBy()
    {
        return $this->signedBy;
    }
}
