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
class TSPService implements AttributeInterface
{
    private $name;
    private $serviceType;
    private $serviceStatus;
    private $statusStartingTime;
    private $identity;
    private $attributes = [];
    private $siExtensions;
    private $serviceHistory;
    private $tspAttributes;

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
                $newSIExtension = new ServiceInformationExtension($siExtension);
                if (!empty($newSIExtension)) {
                    $this->siExtensions[] = $newSIExtension;
                }
            }
        };
        $this->tspAttributes = [];
        if (! empty($tsp)) {
            $this->tspAttributes = $tsp->getAttributes();
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

    public function getIsActive()
    {
        return $this->serviceStatus->getIsActive();
    }

    public function getIsQualified()
    {
        return $this->serviceType->getIsQualified();
    }

    public function getQualifierURIs()
    {
        $uris = [];
        if (!empty($this->siExtensions)) {
            foreach ($this->siExtensions as $siExtension) {
                $uris = array_merge($uris, $siExtension->getQualifierURIs());
            }
        }
        return $uris;
    }

    public function getKeyUsage()
    {
        $keyUsage = [];
        if (!empty($this->siExtensions)) {
            foreach ($this->siExtensions as $siExtension) {
                $keyUsage = array_merge($keyUsage, $siExtension->getKeyUsage());
            }
        }
        return $keyUsage;
    }

    public function getAttributes()
    {
        if (!array_key_exists('name', $this->attributes)) {
            $this->attributes['name'] = $this->getName();
            $this->attributes['type'] = $this->getType();
            if (!empty($this->tspAttributes)) {
                $this->attributes['trustServiceProvider'] = $this->tspAttributes;
            }
            $this->attributes['isQualified'] = $this->getIsQualified();
            $this->attributes['status'] = $this->getStatus();
            $this->attributes['isActive'] = $this->getIsActive();
            $this->attributes['statusStartingTime'] = $this->getDate();
            $this->attributes['x509Certificates'] = [];
            foreach ($this->getX509Certificates() as $certificate) {
                $this->attributes['x509Certificates'][] = [
                  'id' => $certificate->getIdentifier(),
                  'PEM' => $certificate->toPEM()
                ];
            }
            $this->attributes['skiBase64'] = base64_encode($this->getX509SKI());
            $this->attributes['skiHex'] = bin2hex($this->getX509SKI());
            $this->attributes['subjectName'] = $this->getX509SubjectName();
            $this->attributes['serviceHistory'][] = [
                'statusStartingTime' => $this->getDate(),
                'status' => $this->getStatus()
            ];
            foreach ($this->serviceHistory->getInstances() as $serviceStatus) {
                $this->attributes['serviceHistory'][] = [
                  'statusStartingTime' => $serviceStatus->getStartingTime(),
                  'status' => $serviceStatus->getStatus()
                ];
            }
            $qualifierURIs = $this->getQualifierURIs();
            if (!empty($qualifierURIs)) {
                $this->attributes['qualifierURIs'] = $qualifierURIs;
            }
            $keyUsage = $this->getKeyUsage();
            if (!empty($keyUsage)) {
                $this->attributes['keyUsage'] = $keyUsage ;
            }
        }
        return $this->attributes;
    }
}
