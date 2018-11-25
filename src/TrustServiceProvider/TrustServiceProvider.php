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

    /**
     * [__construct description]
     * @param SimpleXMLElement  $tsp     [description]
     */
    public function __construct($tsp)
    {
        $this->name = (string)$tsp->TSPInformation->TSPName->xpath("*[@xml:lang='en']")[0];
        foreach ($tsp->TSPServices->TSPService as $tspService) {
            $newTSPService = new TSPService($tspService);
            $this->services[$newTSPService->getDate()] = $newTSPService;
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
}
