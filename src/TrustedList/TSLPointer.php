<?php

namespace eIDASCertificate\TrustedList;

/**
 *
 */
class TSLPointer extends \Exception
{
    private $tslPointer;
    private $location;
    private $type;
    private $schemeTerritory;
    private $stcrURIs = [];
    private $schemeOperatorNames = [];
    private $serviceDigitalIdentities;
    private $mimeType;

    public function __construct($tslPointer)
    {
        $this->mimeType = (string)$tslPointer->xpath('.//ns3:MimeType')[0];
        $this->location = (string)$tslPointer->TSLLocation;
        $tslAddInfo = $tslPointer->AdditionalInformation;
        $stcrURIs=$tslAddInfo
            ->xpath('.//*[local-name()="SchemeTypeCommunityRules"]')[0]
                ->xpath('.//*[local-name()="URI"]');
        foreach ($stcrURIs as $stcrURI) {
            $this->stcrURIs[
                (string)$stcrURI->attributes('xml',true)['lang']
                ] = (string)$stcrURI;
        };
        $schemeOperatorNames=$tslAddInfo
            ->xpath('.//*[local-name()="SchemeOperatorName"]')[0]
                ->xpath('.//*[local-name()="Name"]');
        foreach ($schemeOperatorNames as $schemeOperatorName) {
            $this->schemeOperatorNames[
                (string)$schemeOperatorName->attributes('xml',true)['lang']
                ] = (string)$schemeOperatorName;
        };

        foreach ($tslPointer->AdditionalInformation->OtherInformation as $tslOtherInfo) {
            // var_dump(sizeof($tslOtherInfo));
            foreach ($tslOtherInfo as $name => $value) {
                switch ($name) {
                    case 'TSLType':
                        $this->type = (string)$value;
                        break;
                    case 'SchemeTerritory':
                        $this->schemeTerritory = (string)$value;
                        break;
                    default:
                        # code...
                        break;
                };
            }
        };
        var_dump([
            "type" => $this->type,
            "territory" => $this->schemeTerritory,
            "uris" => $this->stcrURIs,
            "operatornames" => $this->schemeOperatorNames]);

        // exit;
        // foreach ($tslPointer->ServiceDigitalIdentities->ServiceDigitalIdentity as $SDI) {
        //     $this->serviceDigitalIdentities[] = new ServiceDigitalIdentity($SDI);
        // };
    }

    public function getTSLLocation()
    {
        return $this->tslLocation;
    }

    public function getServiceDigitalIdentities()
    {
        return $this->serviceDigitalIdentities;
    }
    // public function loadTrustedList()
    // {
    //     $tslXml = DataSource::load($this->tslLocation);
    //     $newTL = new TrustedList($tslXml, $tslPointer);
    //     return $newTL;
    // }
    //
    // public function fetchTrustedList()
    // {
    //     $tslXml = DataSource::fetch($this->tslLocation);
    //     $newTL = new TrustedList($tslXml, $tslPointer);
    //     return $newTL;
    // }
}
