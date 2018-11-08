<?php

namespace eIDASCertificate;

use SimpleXMLElement;

/**
 *
 */
class TrustedList
{
    const TrustedListOfListsXML =
      'https://ec.europa.eu/information_society/policy/esignature/trusted-list/tl-mp.xml';
    const TLOLType = 'http://uri.etsi.org/TrstSvc/TrustedList/TSLType/EUlistofthelists';
    // private $TSLPointer;
    private $schemeOperatorName;
    private $schemeTerritory;
    private $TSLLocation;
    private $TSLFormat;
    private $TSLType;
    private $schemeOperators = [];
    private $IsTLOL;
    private $ListIssueDateTime;
    private $NextUpdate;
    private $TrustedLists;

    public function __construct(string $tlxml)
    {
        $tl = new SimpleXMLElement($tlxml);
        $this->schemeTerritory = (string)$tl->SchemeInformation->SchemeTerritory;
        $this->schemeOperatorName = (string)$tl->SchemeInformation->SchemeOperatorName->xpath("*[@xml:lang='en']")[0];
        if ((string)$tl->SchemeInformation->TSLType == self::TLOLType) {
            $this->IsTLOL = true;
        } else {
            $this->IsTLOL = false;
        };
        $this->ListIssueDateTime = strtotime($tl->SchemeInformation->ListIssueDateTime);
        $this->NextUpdate = strtotime($tl->SchemeInformation->NextUpdate->dateTime);
        if ($this->IsTLOL) {
            foreach ($tl->SchemeInformation->PointersToOtherTSL->OtherTSLPointer as $OtherTSLPointer) {
                if ((string)$OtherTSLPointer->AdditionalInformation->OtherInformation[0]->TSLType == self::TLOLType) {
                    foreach ($OtherTSLPointer->AdditionalInformation->OtherInformation as $OtherInfo) {
                        if (strpos($OtherInfo->asXML(), '<ns3:MimeType>')) {
                            $this->TSLFormat = explode("<", explode(">", $OtherInfo->asXML())[2])[0];
                        };
                    }
                } else {
                    foreach ($OtherTSLPointer->AdditionalInformation->OtherInformation as $OtherInfo) {
                        if (strpos($OtherInfo->asXML(), '<ns3:MimeType>')) {
                            if (explode("<", explode(">", $OtherInfo->asXML())[2])[0] == 'application/vnd.etsi.tsl+xml') {
                                $OtherTSLXML = DataSource::getDataFile((string)$OtherTSLPointer->TSLLocation);
                                $TrustedLists[] = new TrustedList($OtherTSLXML);
                            }
                        };
                    }
                }
            }
        }
        print_r([
        "SchemeTerritory" => $this->schemeTerritory,
        "SchemeOperatorName" => $this->schemeOperatorName,
        "IsTLOL" => $this->IsTLOL,
        "ListIssueDateTime" => $this->ListIssueDateTime,
        "NextUpdate" => $this->NextUpdate,
      ]);
    }
    public function constructTLFromPointer(\SimpleXMLElement $OtherTSLPointer)
    {
        $this->TSLPointer = $OtherTSLPointer;
        foreach ($OtherTSLPointer->AdditionalInformation->OtherInformation as $OtherInfo) {
            if (! sizeof($OtherInfo->SchemeTerritory) == 0) {
                $this->SchemeTerritory = $OtherInfo->SchemeTerritory;
            };
            if (! sizeof($OtherInfo->SchemeOperatorName) == 0) {
                $this->schemeOperatorName = $OtherInfo->SchemeOperatorName;
            };
            if (strpos($OtherInfo->asXML(), '<ns3:MimeType>')) {
                $this->TSLFormat = explode("<", explode(">", $OtherInfo->asXML())[2])[0];
            };
        };
    }
    public function displayName()
    {
        return $this->schemeTerritory . ": " . $this->schemeOperatorName .
        " (" . $this->TSLFormat . " " . $this->TSLLocation . ")" . PHP_EOL;
    }
}
