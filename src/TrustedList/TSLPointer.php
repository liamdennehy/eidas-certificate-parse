<?php

namespace eIDASCertificate\TrustedList;

/**
 *
 */
class TSLPointer extends \Exception
{
    private $location;
    private $type;
    private $schemeTerritory;
    private $stcrURIs = [];
    private $schemeTypeCommunityRules = [];
    private $schemeOperatorNames = [];
    private $serviceDigitalIdentities = [];
    private $mimeType;

    public function __construct($tslPointer)
    {
        $this->mimeType = (string)$tslPointer->xpath('.//ns3:MimeType')[0];
        $this->location = (string)$tslPointer->TSLLocation;
        $tslAddInfo = $tslPointer->AdditionalInformation;
        foreach ($tslAddInfo->OtherInformation as $tslOtherInfo) {
            foreach ($tslOtherInfo as $name => $value) {
                switch ($name) {
                    case 'TSLType':
                        $this->type = (string)$value;
                        break;
                    case 'SchemeTerritory':
                        $this->schemeTerritory = (string)$value;
                        break;
                    case 'SchemeOperatorName':
                        foreach ($value->xpath('.//*[local-name()="Name"]') as $soName) {
                            $this->schemeOperatorNames[
                                (string)$soName->attributes('xml', true)['lang']
                                ] = (string)$soName;
                        }
                        break;
                    case 'SchemeTypeCommunityRules':
                        foreach ($value->xpath('.//*[local-name()="URI"]') as $stcrURI) {
                            $this->schemeTypeCommunityRules[
                                (string)$stcrURI->attributes('xml', true)['lang']
                                ] = (string)$stcrURI;
                        }
                        break;
                    default:
                        throw new \Exception("Unknown TSLPointer AdditionalInfo $name", 1);
                        break;
                };
            }
        };
        var_dump([
            "TSLType" => $this->type,
            "SchemeTerritory" => $this->schemeTerritory,
            "SchemeOperatorNames" => $this->schemeOperatorNames,
            "SchemeTypeCommunityRules" => $this->schemeTypeCommunityRules,
            "MimeType" => $this->mimeType,
            "TSLLocation" => $this->location
        ]);
    }

    public function getTSLLocation()
    {
        return $this->tslLocation;
    }

    public function getTSLMimeType()
    {
        return $this->mimeType;
    }

    public function getServiceDigitalIdentities()
    {
        return $this->serviceDigitalIdentities;
    }

    public function getSchemeTerritory()
    {
        return $this->schemeTerritory;
    }
}
