<?php

namespace eIDASCertificate;

/**
 *
 */
class ServiceStatus
{
    private $status;
    private $uri;

    public function __construct($status)
    {
        $this->uri = $status;
        switch ($status) {
          case 'http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/accreditationceased':
            $this->status = 'accreditationceased';
            break;
          case 'http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/accreditationrevoked':
            $this->status = 'accreditationrevoked';
            break;
          case 'http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/accredited':
            $this->status = 'accredited';
            break;
          case 'http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/deprecatedatnationallevel':
            $this->status = 'deprecatedatnationallevel';
            break;
          case 'http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted':
            $this->status = 'granted';
            break;
          case 'http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/recognisedatnationallevel':
            $this->status = 'recognisedatnationallevel';
            break;
          case 'http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/setbynationallaw':
            $this->status = 'setbynationallaw';
            break;
          case 'http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/supervisionceased':
            $this->status = 'supervisionceased';
            break;
          case 'http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/supervisionincessation':
            $this->status = 'supervisionincessation';
            break;
          case 'http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/supervisionrevoked':
            $this->status = 'supervisionrevoked';
            break;
          case 'http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/undersupervision':
            $this->status = 'undersupervision';
            break;
          case 'http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/withdrawn':
            $this->status = 'withdrawn';
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

    public function getURI()
    {
        return $this->uri;
    }

}
