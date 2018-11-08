<?php

namespace eIDASCertificate;

use RobRichards\XMLSecLibs\XMLSecurityDSig;
use RobRichards\XMLSecLibs\XMLSecEnc;
use DOMDocument;

/**
 *
 */
class XMLSig
{
    const XMLDSIGNS = 'http://www.w3.org/2000/09/xmldsig#';

    private $doc;
    private $certificates = [];

    public function __construct(string $xml, array $certificates)
    {
        $this->doc = new DOMDocument();
        $this->doc->loadXML($xml);
        foreach ($certificates as $certificate) {
            $this->certificates[] = openssl_x509_read($certificate);
        }
    }

    public function verifySignature()
    {
        $secDsig = new XMLSecurityDSig();
        $dsig = $secDsig->locateSignature($this->doc);
        if ($dsig === null) {
            throw new \Exception('Cannot locate receipt signature');
        }
        $secDsig->canonicalizeSignedInfo();
        $secDsig->idKeys = array('wsu:Id');
        $secDsig->idNS = array('wsu' => 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd');
        $xpath = new \DOMXPath($this->doc);
        $xpath->registerNamespace('secdsig', self::XMLDSIGNS);
        // This is a hideous kluge as this signature type isn't understood by xmlseclibs
        // As a result it calculates a null-string hash as the digest, and fails validation.
        $query = './/secdsig:Reference[@Type="http://uri.etsi.org/01903#SignedProperties"]';
        $etsirefNodes = $xpath->query($query, $this->doc);
        foreach ($etsirefNodes as $etsirefNode) {
            $etsirefNode->parentNode->removeChild($etsirefNode);
        }
        if (!$secDsig->validateReference()) {
            throw new \Exception('Reference validation failed');
        }
        $key = $secDsig->locateKey();
        if ($key === null) {
            throw new \Exception('Could not locate key in receipt');
        }
        $keyInfo = XMLSecEnc::staticLocateKeyInfo($key, $dsig);
        if (!$keyInfo->key) {
            $key->loadKey($certificate);
        };
        if ($secDsig->verify($key) === 1) {
            if (in_array(
              openssl_x509_fingerprint($keyInfo->getX509Certificate(), 'sha256'),
              $this->getX509Thumbprints()
            )) {
                return true;
            };
        }
    }

    public function getX509Thumbprints()
    {
        $thumbprints = [];
        foreach ($this->certificates as $certificate) {
            $thumbprints[] = openssl_x509_fingerprint($certificate, 'sha256');
        };
        return $thumbprints;
    }
}
