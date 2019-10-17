<?php

namespace eIDASCertificate\TSPService;

use eIDASCertificate\DigitalIdentity\ServiceDigitalIdentity;

/**
 *
 */
class ServiceHistoryInstance
{
    private $serviceType;
    private $serviceStatus;
    private $startingTime;
    // private $serviceName;
    private $digitalIdentity;

    /**
     * [__construct description]
     * @param SimpleXMLElement $historyInstance [description]
     */
    public function __construct($historyInstance)
    {
        $this->serviceType = new ServiceType(
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

    public function getStatus()
    {
        return $this->serviceStatus->getStatus();
    }

    public function getStartingTime()
    {
        return $this->startingTime;
    }

    public function getServiceType()
    {
        return $this->serviceType->getType();
    }
}
