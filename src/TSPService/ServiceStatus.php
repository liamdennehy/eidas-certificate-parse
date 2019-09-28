<?php

namespace eIDASCertificate\TSPService;

/**
 *
 */
class ServiceStatus
{
    private $status;
    private $uri;
    private $isActive;

    /**
     * [__construct description]
     * @param SimpleXMLElement $status [description]
     */
    public function __construct($status)
    {
        $this->uri = $status;
        switch ($status) {
          case 'http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/accreditationceased':
            $this->status = 'accreditationceased';
            $this->isActive = false;
            break;
          case 'http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/accreditationrevoked':
            $this->status = 'accreditationrevoked';
            $this->isActive = false;
            break;
          case 'http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/accredited':
            $this->status = 'accredited';
            $this->isActive = true;
            break;
          case 'http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/deprecatedatnationallevel':
            $this->status = 'deprecatedatnationallevel';
            $this->isActive = false;
            break;
          case 'http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted':
            $this->status = 'granted';
            $this->isActive = true;
            break;
          case 'http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/recognisedatnationallevel':
            $this->status = 'recognisedatnationallevel';
            $this->isActive = true;
            break;
          case 'http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/setbynationallaw':
            $this->status = 'setbynationallaw';
            $this->isActive = true;
            break;
          case 'http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/supervisionceased':
            $this->status = 'supervisionceased';
            $this->isActive = false;
            break;
          case 'http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/supervisionincessation':
            $this->status = 'supervisionincessation';
            $this->isActive = true;
            break;
          case 'http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/supervisionrevoked':
            $this->status = 'supervisionrevoked';
            $this->isActive = false;
            break;
          case 'http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/undersupervision':
            $this->status = 'undersupervision';
            $this->isActive = true;
            break;
          case 'http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/withdrawn':
            $this->status = 'withdrawn';
            $this->isActive = false;
            break;
          default:
            $this->uri = null;
            throw new ParseException("Unknown Service Status Identifier '$status'", 1);
            break;
        }
    }

    public function getStatus()
    {
        return $this->status;
    }

    public function getIsActive()
    {
        return $this->isActive;
    }

    public function getURI()
    {
        return $this->uri;
    }
}
