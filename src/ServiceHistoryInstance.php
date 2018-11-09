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

    public function __construct($historyInstance)
    {
        $serviceType = new ServiceType(
            $historyInstance->ServiceTypeIdentifier
        );
        $this->startingTime = strtotime(
            $historyInstance->StatusStartingTime
        );
    }

    public function getTime()
    {
        return $this->startingTime;
    }
}
