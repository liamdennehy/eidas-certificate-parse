<?php

namespace eIDASCertificate\Certificate;

use eIDASCertificate\Certificate\ExtensionInterface;
use eIDASCertificate\Certificate\ExtensionException;
use eIDASCertificate\OID;
use FG\ASN1\ASNObject;
use FG\ASN1\ExplicitlyTaggedObject;
use FG\ASN1\Universal\PrintableString;

/**
 *
 */
 class CRLDistributionPoints implements ExtensionInterface
 {
     private $binary;
     private $pathLength;
     private $isCA;
     const type = 'crlDistributionPoints';
     const oid = '2.5.29.31';
     const uri = 'https://tools.ietf.org/html/rfc5280#section-4.2.1.13';

     public function __construct($asn1Extension)
     {
         $this->binary = $asn1Extension;
     }

     public function getType()
     {
         return self::type;
     }

     public function getURI()
     {
         return self::uri;
     }

     public function isCA()
     {
         return $this->isCA;
     }

     public function getPathLength()
     {
         if ($this->isCA) {
             return $this->pathLength;
         } else {
             return false;
         }
     }

     public function getBinary()
     {
         return $this->binary;
     }
 }
