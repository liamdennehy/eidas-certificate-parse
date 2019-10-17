<?php

namespace eIDASCertificate;

use eIDASCertificate\AttributeInterface;

/**
 * [Trust Service Provider]
 */
class TrustServiceProvider implements AttributeInterface
{
    private $name;
    private $address;
    private $informationURI;
    private $services = [];
    private $serviceHistory;
    private $parentTSLAtrributes;
    private $attributes = [];

    /**
     * [__construct description]
     * @param SimpleXMLElement  $tsp     [description]
     */
    public function __construct($tsp, $trustedList = null)
    {
        $this->name = (string)$tsp->TSPInformation->TSPName->xpath("*[@xml:lang='en']")[0];
        if (! empty($trustedList)) {
            $this->parentTSLAttributes = $trustedList->getAttributes();
        }
        $this->address = new Address($tsp->TSPInformation->TSPAddress);
        $this->informationURI = new InformationURI($tsp->TSPInformation->TSPInformationURI);
        foreach ($tsp->TSPServices->TSPService as $tspService) {
            $newTSPService = new TSPService($tspService, $this);
            $this->services[$newTSPService->getName()] = $newTSPService;
        };
        ksort($this->services);
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
     * [getTSPServices description]
     * @return array [description]
     */
    public function getTSPServices()
    {
        return $this->services;
    }

    public function getAttributes()
    {
        if (empty($this->attributes)) {
            $this->attributes['name'] = $this->getName();
            if (! empty($this->parentTSLAttributes)) {
                $this->attributes['trustedList'] = $this->parentTSLAttributes;
            }
            $this->attributes['informationURIs'] = $this->getInformationURIs();
        }
        return $this->attributes;
    }

    public function getInformationURIs()
    {
        return $this->informationURI->getInformationURIs();
    }
}
