<?php

namespace eIDASCertificate;

/**
 *
 */
class ServiceStatus
{
    private $status;
    public function __construct($status)
    {
        switch ($status) {
          case 'http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/deprecatedatnationallevel':
            $this->status = 'deprecatedatnationallevel';
            break;
          case 'http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted':
            $this->status = 'granted';
            break;
          case 'http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/recognisedatnationallevel':
            $this->status = 'recognisedatnationallevel';
            break;
          case 'http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/withdrawn':
            $this->status = 'withdrawn';
            break;
          default:
            throw new \Exception("Unknown Service Status Identifier '$status'", 1);

            break;
        }
    }

    public function getStatus()
    {
        return $this->status;
    }
}
