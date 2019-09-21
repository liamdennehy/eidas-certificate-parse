<?php

namespace eIDASCertificate\Certificate;

use eIDASCertificate\Certificate\ExtensionInterface;
use eIDASCertificate\CertificateException;

/**
 *
 */
 class AuthorityKeyIdentifier implements ExtensionInterface
 {
     private $binary;
     private $keyIdentifier;

     const type = 'authorityKeyIdentifier';
     const oid = '2.5.29.35';
     const uri = 'https://tools.ietf.org/html/rfc5280#section-4.2.1.1';

     public function __construct($asn1Extension)
     {
         if (strlen($asn1Extension) == 24) {
             // SHA-1
             $this->keyIdentifier = substr($asn1Extension, 4);
         } else {
             throw new CertificateException("Unsupported keyId length for authorityKeyIdentifier", 1);
         }
     }

     public function getType()
     {
         return self::type;
     }

     public function getURI()
     {
         return self::uri;
     }

     public function getBinary()
     {
         return $this->binary;
     }

     public function getKeyId()
     {
         return $this->keyIdentifier;
     }
 }
