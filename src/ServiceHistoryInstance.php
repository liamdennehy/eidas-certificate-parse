<?php

namespace eIDASCertificate;

/**
 *
 */
class ServiceHistoryInstance
{
    private $serviceType;
    private $serviceStatus;
    private $startingTime;
    private $serviceName;
    private $x509SKI;

    public function __construct($historyInstance)
    {
        $serviceType = new ServiceType(
            $historyInstance->ServiceTypeIdentifier
        );
        $this->startingTime = strtotime(
            $historyInstance->StatusStartingTime
        );
        $this->serviceStatus = new ServiceStatus(
            $historyInstance->ServiceStatus
        );
    }

    public function getTime()
    {
        return $this->startingTime;
    }
}
