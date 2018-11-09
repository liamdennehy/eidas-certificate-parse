<?php

namespace eIDASCertificate;

/**
 *
 */
class ServiceType
{
    private $type;
    private $isQualified;
    public function __construct($identifier)
    {
        // print $identifier . PHP_EOL;
        switch ($identifier) {
          case 'http://uri.etsi.org/TrstSvc/Svctype/ACA':
            $this->type = 'ACA';
            $this->isQualified = false;
            break;
          case 'http://uri.etsi.org/TrstSvc/Svctype/Archiv':
            $this->type = 'Archiv';
            $this->isQualified = false;
            break;
          case 'http://uri.etsi.org/TrstSvc/Svctype/CA/PKC':
            $this->type = 'CA/PKC';
            $this->isQualified = false;
            break;
          case 'http://uri.etsi.org/TrstSvc/Svctype/CA/QC':
            $this->type = 'CA/QC';
            $this->isQualified = true;
            break;
          case 'http://uri.etsi.org/TrstSvc/Svctype/Certstatus/CRL':
            $this->type = 'Certstatus/CRL';
            $this->isQualified = false;
            break;
          case 'http://uri.etsi.org/TrstSvc/Svctype/Certstatus/OCSP':
            $this->type = 'Certstatus/OCSP';
            $this->isQualified = false;
            break;
          case 'http://uri.etsi.org/TrstSvc/Svctype/Certstatus/OCSP/QC':
            $this->type = 'OCSP/QC';
            $this->isQualified = true;
            break;
          case 'http://uri.etsi.org/TrstSvc/Svctype/EDS/Q':
            $this->type = 'EDS/Q';
            $this->isQualified = true;
            break;
          case 'http://uri.etsi.org/TrstSvc/Svctype/EDS/REM/Q':
            $this->type = 'EDS/REM/Q';
            $this->isQualified = true;
            break;
          case 'http://uri.etsi.org/TrstSvc/Svctype/IdV':
            $this->type = 'IdV';
            $this->isQualified = false;
            break;
          case 'http://uri.etsi.org/TrstSvc/Svctype/NationalRootCA-QC':
            $this->type = 'NationalRootCA-QC';
            $this->isQualified = false;
            break;
          case 'http://uri.etsi.org/TrstSvc/Svctype/IdV/nothavingPKIid':
            $this->type = 'IdV/nothavingPKIid';
            $this->isQualified = false;
            break;
          case 'http://uri.etsi.org/TrstSvc/Svctype/PSES/Q':
            $this->type = 'PSES/Q';
            $this->isQualified = true;
            break;
          case 'http://uri.etsi.org/TrstSvc/Svctype/QESValidation/Q':
            $this->type = 'QESValidation/Q';
            $this->isQualified = true;
            break;
          case 'http://uri.etsi.org/TrstSvc/Svctype/RA':
            $this->type = 'RA';
            $this->isQualified = false;
            break;
          case 'http://uri.etsi.org/TrstSvc/Svctype/SignaturePolicyAuthority':
            $this->type = 'SignaturePolicyAuthority';
            $this->isQualified = false;
            break;
          case 'http://uri.etsi.org/TrstSvd/Svctype/TLIssuer':
            $this->type = 'Unknown';
            $this->isQualified = false;
            break;
          case 'http://uri.etsi.org/TrstSvc/Svctype/TSA':
            $this->type = 'TSA';
            $this->isQualified = false;
            break;
          case 'http://uri.etsi.org/TrstSvc/Svctype/TSA/QTST':
            $this->type = 'TSA/QTST';
            $this->isQualified = true;
            break;
          case 'http://uri.etsi.org/TrstSvc/Svctype/TSA/TSS-AdESQCandQES':
            $this->type = 'TSA/TSS-AdESQCandQES';
            $this->isQualified = false;
            break;
          case 'http://uri.etsi.org/TrstSvc/Svctype/TSA/TSS-QC':
            $this->type = 'TSA/TSS-QC';
            $this->isQualified = false;
            break;
          case 'http://uri.etsi.org/TrstSvc/Svctype/unspecified':
            $this->type = 'Unspecified';
            $this->isQualified = false;
            break;
          default:
            throw new ParseException("Unknown Service Type Identifier '$identifier'", 1);

            break;
        };
        // return ["Type" => $this->getType(),"isQualified" => $this->IsQualified()];
    }

    public function getType()
    {
        return $this->type;
    }

    public function IsQualified()
    {
        return $this->isQualified;
    }
}
