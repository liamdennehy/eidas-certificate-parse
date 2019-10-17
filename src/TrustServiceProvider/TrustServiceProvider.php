<?php

namespace eIDASCertificate;

use eIDASCertificate\AttributeInterface;
use eIDASCertificate\ParseException;

/**
 * [Trust Service Provider]
 */
class TrustServiceProvider implements AttributeInterface
{
    private $name;
    private $address;
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
        foreach ($tsp->TSPServices->TSPService as $tspService) {
            try {
                $newTSPService = new TSPService($tspService, $this);
            } catch (ParseException $e) {
                // Critical info not understood, do not process TSPService
                print 'Critical error parsing TSPService: '.
                    $e->getMessage();
            }
            $this->services[$newTSPService->getName()] = $newTSPService;
        };
        $this->address = new Address($tsp->TSPInformation->TSPAddress);
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
        }
        return $this->attributes;
    }
}
