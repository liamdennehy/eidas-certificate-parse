<?php

namespace eIDASCertificate\Certificate;

use eIDASCertificate\Certificate\ExtensionInterface;
use eIDASCertificate\OID;
use FG\ASN1\ASNObject;

/**
 *
 */
 class KeyUsage implements ExtensionInterface
 {
     const type = 'keyUsage';
     const oid = '2.5.29.15';
     const uri = 'https://tools.ietf.org/html/rfc5280#section-4.2.1.3';

     public function __construct($keyUsageString)
     {
         $this->keyUsage = explode(", ", $keyUsageString);
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
         return false; // Unable to use binary, so deriving this from parsed
     }
 }
