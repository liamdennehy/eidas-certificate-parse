<?php

namespace eIDASCertificate;

use FG\ASN1\ASN1Object;
use FG\ASN1\OID;

// use eIDASCertificate\OID => LocalOIDs;

/**
 *
 */
class QCStatements
{
    private $asn1Object;

    public function __construct($asn1Statement)
    {
        $this->asn1Object = ASN1Object::fromBinary($asn1Statement);
        if ($this->getType() != \eIDASCertificate\OID::PKIX_QCSYNTAX_V2) {
            print "Cannot parse QCStatements (unkown format ".$this->getType().")";
        } else {
            $this->type = 'id-qcs-pkixQCSyntax-v2';
        }
    }

    public function getType()
    {
        return $this->asn1Object->getContent()[0]->getContent()[0]->getContent();
    }

    public function getTypes()
    {
        $types = [];
        foreach ($this->asn1Object->getContent() as $key => $value) {
            $oidValue = $value->getContent()[0]->getContent();
            $name = OID::getName($oidValue);
            if ($name == "{$oidValue} (unknown)") {
                $name = \eIDASCertificate\OID::getName($oidValue);
            }
            $types[$key] = $name;
        }
        return $types;
    }
//     public function new($asn1Statement)
//     {
//         return $asn1Statement;
//     }
}
