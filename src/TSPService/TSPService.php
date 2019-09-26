<?php

namespace eIDASCertificate;

use eIDASCertificate\TSPService\ServiceType;
use eIDASCertificate\TSPService\ServiceStatus;
use eIDASCertificate\TSPService\ServiceHistory;
use eIDASCertificate\TSPService\ServiceInformationExtension;
use eIDASCertificate\DigitalIdentity\ServiceDigitalIdentity;

/**
 *
 */
class TSPService
{
    private $name;
    private $serviceType;
    private $serviceStatus;
    private $startingTime;
    private $identities;
    private $siExtensions;
    private $serviceHistory;
    private $tsp;

    /**
     * [__construct description]
     * @param SimpleXMLElement  $tspService [description]
     */
    public function __construct($tspService, $tsp = null)
    {
        $serviceInformation = $tspService->ServiceInformation;
        $this->name = (string)$serviceInformation->ServiceName->xpath("*[@xml:lang='en']")[0];
        $this->serviceType = new ServiceType(
            (string)$serviceInformation->ServiceTypeIdentifier
        );
        $this->serviceStatus = new ServiceStatus(
            (string)$serviceInformation->ServiceStatus
        );
        $this->startingTime = strtotime((string)$serviceInformation->StatusStartingTime);
        foreach ($serviceInformation->ServiceDigitalIdentity as $identity) {
            $this->identities[] = new ServiceDigitalIdentity($identity);
        };
        $this->serviceHistory = new ServiceHistory(
            $tspService->ServiceHistory
        );
        if (count($serviceInformation->ServiceInformationExtensions)) {
            foreach ($serviceInformation->ServiceInformationExtensions->Extension as $siExtension) {
                // Apparently https://stackoverflow.com/questions/27742595/php-best-way-to-stop-constructor
                try {
                    $newSIExtension = new ServiceInformationExtension($siExtension);
                    $this->siExtensions[] = $newSIExtension;
                } catch (SafeException $e) {
                    // continue;
                }
            }
        };

        $this->tsp = [];
        if (! empty($tsp)) {
            $this->tsp = $tsp->getTSPAtrributes();
        }
    }

    /**
     * [getSummary description]
     * @return array [description]
     */
    public function getSummary()
    {
        return [
            "name" => $this->name,
            "type" => $this->serviceType->getType(),
            "isQualified" => $this->serviceType->isQualified(),
            "status" => $this->status->getStatus(),
            "startingTime" => $this->startingTime,
            "identities" => $this->identities,
            "siExtensions" => $this->siExtensions,
            "history" => $this->serviceHistory
        ];
    }

    public function getDate()
    {
        return $this->startingTime;
    }

    /**
     * [getIdentities description]
     * @return ServiceDigitalIdentity[] [description]
     */
    public function getIdentities()
    {
        return $this->identities;
    }

    /**
     * [getName description]
     * @return string [description]
     */
    public function getName()
    {
        return $this->name;
    }

    /**
     * [getStatus description]
     * @return string [description]
     */
    public function getStatus()
    {
        return $this->serviceStatus->getStatus();
    }

    /**
     * [getType description]
     * @return string [description]
     */
    public function getType()
    {
        return $this->serviceType->getType();
    }

    /**
     * [getTSPServiceHistory description]
     * @return ServiceHistory [description]
     */
    public function getTSPServiceHistory()
    {
        return $this->serviceHistory;
    }

    public function getTSPServiceAttributes()
    {
        return [
          'TSP' => $this->tsp
        ];
    }
}
