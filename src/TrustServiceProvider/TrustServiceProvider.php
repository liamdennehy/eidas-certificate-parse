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
    private $names;
    private $tradeNames;
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
        $this->names = new Names($tsp->TSPInformation->TSPName);
        $this->tradeNames = new Names($tsp->TSPInformation->TSPTradeName);
        foreach ($tsp->TSPServices->TSPService as $tspService) {
            // try {
            $newTSPService = new TSPService($tspService, $this);
            // } catch (ParseException $e) {
            //     // Critical info not understood, do not process TSPService
            //     print 'Critical error parsing TSPService: '.
            //         $e->getMessage();
            // }
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

    public function getNames()
    {
        return $this->names->getNames();
    }

    public function getTradeNames()
    {
        return $this->tradeNames->getNames();
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
            $this->attributes['names'] = $this->getNames();
            $tradeNames = $this->getTradeNames();
            if (!empty($tradeNames)) {
                $this->attributes['tradeNames'] = $this->getTradeNames();
            }
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
