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
    private $statusStartingTime;
    private $identity;
    private $attributes;
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
        $this->statusStartingTime = strtotime((string)$serviceInformation->StatusStartingTime);
        if (sizeof($serviceInformation->ServiceDigitalIdentity) > 1) {
            throw new ParseException("Multiple Service Identities in '$this->name '", 1);
        }
        $this->identity = new ServiceDigitalIdentity($serviceInformation->ServiceDigitalIdentity[0]);
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
            $this->tsp = $tsp->getTSPAttributes();
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
            "startingTime" => $this->statusStartingTime,
            "identity" => $this->identity,
            "siExtensions" => $this->siExtensions,
            "history" => $this->serviceHistory
        ];
    }

    public function getDate()
    {
        return $this->statusStartingTime;
    }

    /**
     * [getIdentities description]
     * @return ServiceDigitalIdentity[] [description]
     */
    public function getIdentity()
    {
        return $this->identity;
    }

    /**
     * [getName description]
     * @return string [description]
     */
    public function getName()
    {
        return $this->name;
    }

    public function getX509Certificates()
    {
        return $this->identity->getX509Certificates();
    }

    public function getX509SubjectName()
    {
        return $this->identity->getX509SubjectName();
    }

    public function getX509SKI()
    {
        return $this->identity->getX509SKI();
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
        if (empty($this->attributes)) {
            $this->attributes = ['TSP' => $this->tsp];
            $this->attributes['ServiceName'] = $this->getName();
            $this->attributes['ServiceStatus'] = $this->getStatus();
            $this->attributes['StatusStartingTime'] = $this->getDate();
            $this->attributes['Certificates'] = [];
            foreach ($this->getX509Certificates() as $certificate) {
                $this->attributes['Certificates'][$certificate->getIdentifier()] = $certificate->toPEM();
            }
            $this->attributes['SKI'] = $this->getX509SKI();
            $this->attributes['SubjectName'] = $this->getX509SubjectName();
        }
        return $this->attributes;
    }
}
