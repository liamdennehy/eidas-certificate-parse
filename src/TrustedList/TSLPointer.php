<?php

namespace eIDASCertificate\TrustedList;

use eIDASCertificate\DigitalIdentity\ServiceDigitalIdentity;

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
    private $fileType;

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
        // var_dump($this->schemeTerritory);
        foreach ($tslPointer->ServiceDigitalIdentities->ServiceDigitalIdentity as $SDI) {
            // foreach ($SDI->xpath('.//*[local-name()="DigitalId"]') as $dID) {
            //     foreach ($dID->children() as $name => $nothing) {
            //         switch ($name) {
            //             case 'X509Certificate':
            //                 break;
            //             case 'X509SubjectName':
            //                 break;
            //             case 'X509SKI':
            //                 break;
            //
            //             default:
            //                 throw new \Exception("Unknown DigitalIdentity Type $name on TSLPointer $this->schemeTerritory", 1);
            //
            //                 break;
            //         };
            //     };
            // };

            $this->serviceDigitalIdentities[] = new ServiceDigitalIdentity($SDI);
        };

        switch ($this->mimeType) {
            case 'application/vnd.etsi.tsl+xml':
                $this->fileType = 'xml';
                break;
            case 'application/pdf':
                $this->fileType = 'pdf';
                break;
            default:
                throw new \Exception("Unknown TSL Format $this->mimeType", 1);

                break;
        }
    }

    public function getTSLLocation()
    {
        return $this->location;
    }

    public function getTSLMimeType()
    {
        return $this->mimeType;
    }

    public function getTSLFileType()
    {
        return $this->fileType;
    }

    public function getServiceDigitalIdentities()
    {
        return $this->serviceDigitalIdentities;
    }

    public function getSchemeTerritory()
    {
        return $this->schemeTerritory;
    }

    public function getSchemeOperatorName($lang = 'en')
    {
        return $this->schemeOperatorNames[$lang];
    }

    public function getName()
    {
        return $this->getSchemeTerritory() . ": " . $this->getSchemeOperatorName();
    }

    public function dumpTSLPointer()
    {
        // foreach ($this->serviceDigitalIdentities as $id) {
        //     return($id->getX509Certificates());
        // }
        return ([
            "TSLType" => $this->type,
            "SchemeTerritory" => $this->schemeTerritory,
            "SchemeOperatorNames" => $this->schemeOperatorNames,
            "SchemeTypeCommunityRules" => $this->schemeTypeCommunityRules,
            "MimeType" => $this->mimeType,
            "TSLLocation" => $this->location,
            "IDs" => $this->serviceDigitalIdentities
        ]);
    }
}
