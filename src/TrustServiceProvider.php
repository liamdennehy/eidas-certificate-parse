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
    public function __construct($tsp)
    {
        $this->name = $tsp->TSPInformation->TSPName->xpath("*[@xml:lang='en']")[0];
        foreach ($tsp->TSPServices->TSPService as $tspService) {
            $services[] = new TSPService($tspService);
        }
        $this->serviceHistory = new ServiceHistory(
          $tspService->ServiceHistory
        );
    }
}
