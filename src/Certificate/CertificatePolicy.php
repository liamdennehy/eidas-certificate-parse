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
    private $vendor;
    private $oid;
    private $binary;

    const vendor_ETSI = 'ETSI';
    const vendor_CAB = 'CA/Browser Forum';

    public function __construct($policy)
    {
        $this->oid = $policy->at(0)->asObjectIdentifier()->oid();
        $this->name = OID::getName($this->oid);
        switch ($this->name) {
            case 'qcpWebPSD2':
                $this->description =
                  'PSD2 qualified website authentication certificate';
                $this->url = 'https://www.etsi.org/deliver/etsi_ts/119400_119499/119495/01.03.02_60/ts_119495v010302p.pdf#chapter-6.1';
                $this->vendor = self::vendor_ETSI;
                break;
            case 'extended_validation':
              $this->description =
                'Certificate issued in compliance with the Extended Validation Guidelines';
              $this->url = 'https://cabforum.org/object-registry/';
              $this->vendor = self::vendor_CAB;
              break;
            case 'organization_validation':
              $this->description =
                'Compliant with Baseline Requirements – Organization identity asserted';
              $this->url = 'https://cabforum.org/object-registry/';
              $this->vendor = self::vendor_CAB;
              break;
            default:
                throw new ParseException("Unrecognised", 1);
                break;
          }
        $this->binary = $policy->toDER();
    }

    public function getAttributes()
    {
        return [
            'oid' => $this->oid,
            'name' => $this->name,
            'description' => $this->description,
            'vendor' => $this->vendor,
            'url' => $this->url
        ];
    }
}
