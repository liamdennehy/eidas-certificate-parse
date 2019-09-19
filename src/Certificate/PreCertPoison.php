<?php

namespace eIDASCertificate\Certificate;

use eIDASCertificate\Certificate\ExtensionInterface;
use eIDASCertificate\OID;
use FG\ASN1\ASNObject;

/**
 *
 */
 class PreCertPoison implements ExtensionInterface
 {
     private $binary;
     const type = 'preCertPoison';
     const oid = '1.3.6.1.4.1.11129.2.4.3';
     const uri = 'https://tools.ietf.org/html/rfc6962#section-3.1';

     public function __construct($asn1Extension)
     {
         $this->binary = ASNObject::fromBinary($asn1Extension);
     }

     public function getType()
     {
         return self::type;
     }

     public function getURI()
     {
         return self::uri;
     }
 }
