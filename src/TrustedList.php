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
    private $isTLOL;
    private $listIssueDateTime;
    private $nextUpdate;
    private $TrustedLists = [];
    private $digitalIdentities = [];

    public function __construct(string $tlxml, $digitalIdentities = null)
    {
        $tl = new SimpleXMLElement($tlxml);
        $this->schemeTerritory = (string)$tl->SchemeInformation->SchemeTerritory;
        $this->schemeOperatorName = (string)$tl->SchemeInformation->SchemeOperatorName->xpath("*[@xml:lang='en']")[0];
        if ((string)$tl->SchemeInformation->TSLType == self::TLOLType) {
            $this->isTLOL = true;
        } else {
            $this->isTLOL = false;
        };
        $this->listIssueDateTime = strtotime($tl->SchemeInformation->ListIssueDateTime);
        $this->nextUpdate = strtotime($tl->SchemeInformation->NextUpdate->dateTime);
        if ($this->isTLOL) {
            foreach ($tl->SchemeInformation->PointersToOtherTSL->OtherTSLPointer as $otherTSLPointer) {
                if ((string)$otherTSLPointer->AdditionalInformation->OtherInformation[0]->TSLType == self::TLOLType) {
                    // $this->digitalIdentities = $otherTSLPointer->ServiceDigitalIdentities;
                    foreach ($otherTSLPointer->AdditionalInformation->OtherInformation as $OtherInfo) {
                        if (strpos($OtherInfo->asXML(), '<ns3:MimeType>')) {
                            $this->TSLFormat = explode("<", explode(">", $OtherInfo->asXML())[2])[0];
                        };
                    }
                } else {
                    $TSLEntry = $this->getTSL($otherTSLPointer);
                    if (! is_null($TSLEntry)) {
                        $newTSL = $this->getTSL($otherTSLPointer);
                        if ( $newTSL ) {
                          $this->trustedLists[$newTSL->getSchemeOperatorName()] = $newTSL;
                        };
                    };
                }
            }
        };
        if ( $digitalIdentities ) {
          foreach ($digitalIdentities->xpath('*') as $digitalId) {
            $this->digitalIdentities[] = new ServiceDigitalIdentity($digitalId);
          };
        }
    }

    private function getTSL($TSLPointer)
    {
        foreach ($TSLPointer->AdditionalInformation->OtherInformation as $OtherInfo) {
            if (strpos($OtherInfo->asXML(), '<ns3:MimeType>')) {
                if (explode("<", explode(">", $OtherInfo->asXML())[2])[0] == 'application/vnd.etsi.tsl+xml') {
                    $TSLXML = DataSource::getDataFile((string)$TSLPointer->TSLLocation);
                    $newTL = new TrustedList($TSLXML, $TSLPointer->ServiceDigitalIdentities);
                    return $newTL;
                }
            };
        };
        return null;
    }

    public function getdigitalIdentities() {
      return $this->digitalIdentities;
    }
    // public function constructTLFromPointer(\SimpleXMLElement $OtherTSLPointer)
    // {
    //     $this->TSLPointer = $OtherTSLPointer;
    //     foreach ($OtherTSLPointer->AdditionalInformation->OtherInformation as $OtherInfo) {
    //         if (! sizeof($OtherInfo->SchemeTerritory) == 0) {
    //             $this->SchemeTerritory = $OtherInfo->SchemeTerritory;
    //         };
    //         if (! sizeof($OtherInfo->SchemeOperatorName) == 0) {
    //             $this->schemeOperatorName = $OtherInfo->SchemeOperatorName;
    //         };
    //         if (strpos($OtherInfo->asXML(), '<ns3:MimeType>')) {
    //             $this->TSLFormat = explode("<", explode(">", $OtherInfo->asXML())[2])[0];
    //         };
    //     };
    // }
    public function displayName()
    {
        return $this->schemeTerritory . ": " . $this->schemeOperatorName .
        " (" . $this->TSLFormat . " " . $this->TSLLocation . ")" . PHP_EOL;
    }

    public function getSchemeTerritory() {
      return $this->schemeTerritory;
    }

    public function getSchemeOperatorName() {
      return $this->schemeOperatorName;
    }

    public function isTLOL() {
      return $this->isTLOL;
    }

    public function getListIssueDateTime() {
      return $this->listIssueDateTime;
    }

    public function getNextUpdate() {
      return $this->nextUpdate;
    }

    public function TrustedLists() {
      return $this->trustedLists;
    }
}
