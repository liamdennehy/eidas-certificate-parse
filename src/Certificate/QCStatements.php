<?php

namespace eIDASCertificate;

use FG\ASN1\ASN1Object;

/**
 *
 */
class QCStatements
{
    private $asn1Object;
    public function __construct($asn1Statement)
    {
      $this->asn1Object = ASN1Object::fromBinary($asn1Statement);

    }

    public function getType()
    {
      return $this->asn1Object->getContent()[0]->getContent()[0]->getContent();

    }
//     public function new($asn1Statement)
//     {
//         return $asn1Statement;
//     }

}
