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
    private $verbose;

    /**
     * [__construct description]
     * @param SimpleXMLElement  $tsp     [description]
     * @param boolean $verbose [description]
     */
    public function __construct($tsp, $verbose = false)
    {
        // $this->verbose = $verbose;
        $this->name = (string)$tsp->TSPInformation->TSPName->xpath("*[@xml:lang='en']")[0];
        if ($verbose) {
            print '    ' . $this->getName() . PHP_EOL;
        };
        foreach ($tsp->TSPServices->TSPService as $tspService) {
            $newTSPService = new TSPService($tspService, $verbose);
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
