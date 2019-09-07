<?php

namespace eIDASCertificate;

use FG\ASN1\ASNObject;
// use FG\ASN1\OID;

use eIDASCertificate\OID;

/**
 *
 */
class QCStatements
{
    private $asn1Object;

    public function __construct($asn1Statement)
    {
        $this->asn1Object = ASNObject::fromBinary($asn1Statement);
        foreach ($this->asn1Object as $statement) {
            QCStatement::fromASNObject($statement);
        }
    }

    // public function getType()
    // {
    //     return $this->asn1Object->getContent()[0]->getContent()[0]->getContent();
    // }

    // public function getTypes()
    // {
    //     $types = [];
    //     foreach ($this->asn1Object->getContent() as $key => $value) {
    //         $oidValue = $value->getContent()[0]->getContent();
    //         // $name = OID::getName($oidValue);
    //         // print $name . PHP_EOL;
    //         // if ($name == "{$oidValue} (unknown)") {
    //         print "boo" . PHP_EOL;
    //         $name = \eIDASCertificate\OID::getName($oidValue);
    //         // }
    //         $types[$key] = $name;
    //     }
    //     return $types;
    // }
//     public function new($asn1Statement)
//     {
//         return $asn1Statement;
//     }
}
