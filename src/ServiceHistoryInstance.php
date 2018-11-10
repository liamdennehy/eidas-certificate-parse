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
    private $digitalIdentity;

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
        $this->digitalIdentity = new ServiceDigitalIdentity($historyInstance->ServiceDigitalIdentity);
    }

    public function getTime()
    {
        return $this->startingTime;
    }

}
