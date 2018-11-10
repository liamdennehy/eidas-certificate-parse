<?php

namespace eIDASCertificate;

/**
 *
 */
class TSPService
{
    private $name;
    private $serviceType;
    private $status;
    private $startingTime;
    private $identities;
    private $siExtensions;

    public function __construct($tspService, $verbose = false)
    {
        $serviceInformation = $tspService->ServiceInformation;
        $this->name = (string)$serviceInformation->ServiceName->xpath("*[@xml:lang='en']")[0];
        $this->serviceType = new ServiceType(
            (string)$serviceInformation->ServiceTypeIdentifier
        );
        $this->status = new ServiceStatus(
            (string)$serviceInformation->ServiceStatus
        );
        $this->startingTime = strtotime((string)$serviceInformation->StatusStartingTime);
        foreach ($serviceInformation->ServiceDigitalIdentity->DigitalId as $identity) {
            $this->identities[] = new ServiceDigitalIdentity($identity);
        };
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
                    continue;
                }
            }
        };
    }

    public function getService()
    {
        return [
          "type" => $this->serviceType->getType(),
          "isQualified" => $this->serviceType->isQualified(),
          "status" => $this->status->getStatus(),
          "startingTime" => $this->startingTime,
          "identities" => $this->identities,
          "siExtensions" => $this->siExtensions
        ];
    }

    public function getDate()
    {
        return $this->startingTime;
    }

    public function getName()
    {
        return $this->name;
    }
}
