<?php

namespace eIDASCertificate;

/**
 * [Trust Service Provider]
 */
class TrustServiceProvider
{
    private $name;
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
            $this->parentTSLAttributes = $trustedList->getTrustedListAtrributes();
        }
        foreach ($tsp->TSPServices->TSPService as $tspService) {
            $newTSPService = new TSPService($tspService, $this);
            $this->services[$newTSPService->getName()] = $newTSPService;
        };
        sort($this->services);
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

    public function getTSPAttributes()
    {
        if (empty($this->attributes)) {
            $this->attributes['TrustServiceProvider'] = $this->getName();
            if (! empty($this->parentTSLAttributes)) {
                $this->attributes['TrustedList'] = $this->parentTSLAttributes;
            }
        }
        return $this->attributes;
    }
}
