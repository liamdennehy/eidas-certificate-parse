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
    private $parentTSL;

    /**
     * [__construct description]
     * @param SimpleXMLElement  $tsp     [description]
     */
    public function __construct($tsp, $trustedList)
    {
        $this->name = (string)$tsp->TSPInformation->TSPName->xpath("*[@xml:lang='en']")[0];
        $this->parentTSL = [];
        $this->parentTSL['SchemeTerritory'] = $trustedList->getSchemeTerritory();
        $this->parentTSL['SchemeOperatorName'] = $trustedList->getSchemeOperatorName();
        $this->parentTSL['TSLSequenceNumber'] = $trustedList->getSequenceNumber();
        $this->parentTSL['TSLSignedBy'] = $trustedList->getSignedByHash();
        if (! empty($trustedList->getParentTrustedListAtrributes())) {
            $this->parentTSL['ParentTSL'] = $trustedList->getParentTrustedListAtrributes();
        }
        foreach ($tsp->TSPServices->TSPService as $tspService) {
            $newTSPService = new TSPService($tspService, $this);
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

    public function getTSPAtrributes()
    {
        return [
          'ParentTSL' => $this->parentTSL,
          'TrustServiceProvider' => $this->getName()
        ];
    }
}
