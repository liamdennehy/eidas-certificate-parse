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

    public function __construct($tsp)
    {
        // $this->verbose = $verbose;
        $this->name = (string)$tsp->TSPInformation->TSPName->xpath("*[@xml:lang='en']")[0];
        foreach ($tsp->TSPServices->TSPService as $tspService) {
            $newTSPService = new TSPService($tspService);
            $this->services[$newTSPService->getDate()] = $newTSPService;
        };
        sort($this->services);
        $this->serviceHistory = new ServiceHistory(
          $tspService->ServiceHistory
        );
    }

    public function getName()
    {
        return $this->name;
    }

    public function getServices()
    {
        $services = [];
        foreach ($this->services as $service) {
            $services[] = $service->getService();
        };
        return $services;
    }
}
