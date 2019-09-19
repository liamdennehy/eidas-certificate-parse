<?php

namespace eIDASCertificate\Certificate;

use eIDASCertificate\Certificate\ExtensionInterface;
use eIDASCertificate\Certificate\ExtensionException;
use eIDASCertificate\OID;
use FG\ASN1\ASNObject;

/**
 *
 */
 class BasicConstraints implements ExtensionInterface
 {
     private $binary;
     private $pathLength;
     private $isCA;
     const type = 'basicConstraints';
     const oid = '2.5.29.19';
     const uri = 'https://tools.ietf.org/html/rfc5280#section-4.2.1.9';

     public function __construct($asn1Extension)
     {
         $constraints = ASNObject::fromBinary($asn1Extension);
         if (sizeof($constraints) > 1 && get_class($constraints[1]) == "FG\ASN1\Universal\Boolean") {
             if ($constraints[1]->getContent() == "TRUE") {
                 $this->isCA = true;
                 $this->pathLength = $constraints[2]->getContent();
             }
         } else {
             $this->isCA = false;
         }
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
 }
