<?php

namespace eIDASCertificate;

/**
 *
 */
class TSPService
{
    private $serviceType;
    private $status;
    private $startingTime;

    public function __construct($tspService)
    {
        $this->serviceType = new ServiceType(
            (string)$tspService->ServiceInformation->ServiceTypeIdentifier
        );
        $this->status = new ServiceStatus(
            (string)$tspService->ServiceInformation->ServiceStatus
        );
        $this->startingTime = strtotime((string)$tspService->ServiceInformation->StatusStartingTime);
    }

    public function getService()
    {
        return [
          "type" => $this->serviceType->getType(),
          "isQualified" => $this->serviceType->isQualified(),
          "status" => $this->status->getStatus(),
          "startingTime" => $this->startingTime
        ];
    }

    public function getDate()
    {
        return $this->startingTime;
    }
}
