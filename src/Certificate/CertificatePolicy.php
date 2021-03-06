<?php

namespace eIDASCertificate\Certificate;

use eIDASCertificate\ParseException;
use eIDASCertificate\Finding;
use eIDASCertificate\OID;
use ASN1\Type\UnspecifiedType;

class CertificatePolicy
{
    private $description;
    private $url;
    private $name;
    private $oid;
    private $binary;

    public function __construct($policy)
    {
        $this->oid = $policy->at(0)->asObjectIdentifier()->oid();
        $this->name = OID::getName($this->oid);
        switch ($this->name) {
            case 'qcpWebPSD2':
                $this->description =
                  'PSD2 qualified website authentication certificate';
                $this->url = 'https://www.etsi.org/deliver/etsi_ts/119400_119499/119495/01.03.02_60/ts_119495v010302p.pdf#chapter-6.1';
                break;
            case 'EVCP':
              $this->description =
                'Consistent with EV Certificates Guidelines issued by the CAB Forum';
              $this->url = 'https://www.etsi.org/deliver/etsi_ts/102000_102099/102042/02.04.01_60/ts_102042v020401p.pdf#chapter-5.2';
              break;
            case 'extended_validation':
              $this->description =
                'Certificate issued in compliance with the Extended Validation Guidelines';
              $this->url = 'https://cabforum.org/object-registry/';
              break;
            case 'organization_validation':
              $this->description =
                'Compliant with Baseline Requirements – Organization identity asserted';
              $this->url = 'https://cabforum.org/object-registry/';
              break;
            default:
                $vendor = OID::getVendorFromOID($this->oid);
                if ($vendor == 'unknown') {
                    throw new ParseException("Certificate Policy from unknown vendor as oid '$this->oid'", 1);
                } else {
                    throw new ParseException("Unrecognised '$vendor' Certificate Policy as oid '$this->oid'", 1);
                }
                break;
          }
        $this->binary = $policy->toDER();
    }

    public function getVendor()
    {
        return OID::getVendorFromOID($this->oid);
    }

    public function getOID()
    {
        return $this->oid;
    }

    public function getAttributes()
    {
        return [
            'oid' => $this->oid,
            'name' => $this->name,
            'description' => $this->description,
            'vendor' => $this->getVendor(),
            'url' => $this->url
        ];
    }
}
