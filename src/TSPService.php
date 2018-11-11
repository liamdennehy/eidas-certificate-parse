<?php

namespace eIDASCertificate;

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

    /**
     * [__construct description]
     * @param SimpleXMLElement  $tspService [description]
     * @param boolean $verbose    [description]
     */
    public function __construct($tspService, $verbose = false)
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
                    if ($verbose) {
                        print '        ' . $newSIExtension->getURI() . PHP_EOL;
                    };
                    $this->siExtensions[] = $newSIExtension;
                } catch (SafeException $e) {
                    // continue;
                }
            }
        };
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

    public function getIdentities()
    {
        return $this->identities;
    }

    public function getName()
    {
        return $this->name;
    }

    public function getStatus()
    {
        return $this->serviceStatus->getStatus();
    }

    public function getType()
    {
        return $this->serviceType->getType();
    }

    public function getTSPServiceHistory()
    {
        return $this->serviceHistory;
    }
}
