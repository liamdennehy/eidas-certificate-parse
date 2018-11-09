<?php

namespace eIDASCertificate;

/**
 *
 */
class TSPService
{
    private $identifier;
    private $status;
    public function __construct($tspService)
    {
        $this->identifier = new ServiceTypeIdentifier(
            (string)$tspService->ServiceInformation->ServiceTypeIdentifier
        );
        $this->status = new ServiceStatus(
            (string)$tspService->ServiceInformation->ServiceStatus    
        );
    }
}
