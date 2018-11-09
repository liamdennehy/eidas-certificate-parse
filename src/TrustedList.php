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

    public function __construct(string $tlxml, $tslPointer = null)
    {
        $tl = new SimpleXMLElement($tlxml);
        $this->schemeTerritory = (string)$tl->SchemeInformation->SchemeTerritory;
        $this->schemeOperatorName =
          (string)$tl
            ->SchemeInformation
              ->SchemeOperatorName
                ->xpath("*[@xml:lang='en']")[0];
        if ((string)$tl->SchemeInformation->TSLType == self::TLOLType) {
            $this->isTLOL = true;
        } else {
            $this->isTLOL = false;
        };
        $this->listIssueDateTime = strtotime(
            $tl->SchemeInformation->ListIssueDateTime
        );
        $this->nextUpdate = strtotime(
            $tl->SchemeInformation->NextUpdate->dateTime
        );
        if ($this->isTLOL) {
            foreach (
                $tl->SchemeInformation->PointersToOtherTSL->OtherTSLPointer
                as $otherTSLPointer
            ) {
                if (
                    (string)$otherTSLPointer
                      ->AdditionalInformation
                        ->OtherInformation[0]
                          ->TSLType
                    == self::TLOLType
                ) {
                    foreach (
                        $otherTSLPointer
                          ->AdditionalInformation
                            ->OtherInformation
                        as $OtherInfo
                    ) {
                        if (strpos($OtherInfo->asXML(), '<ns3:MimeType>')) {
                            $this->TSLFormat = explode("<", explode(">", $OtherInfo->asXML())[2])[0];
                        };
                    };
                    foreach ($otherTSLPointer->ServiceDigitalIdentities as $digitalId) {
                        $this->digitalIdentities[] = new ServiceDigitalIdentity($digitalId);
                    };
                    $this->TSLLocation = (string)$otherTSLPointer->TSLLocation;
                } else {
                    $TSLEntry = $this->getTSL($otherTSLPointer);
                    if (! is_null($TSLEntry)) {
                        $newTSL = $this->getTSL($otherTSLPointer);
                        if ($newTSL) {
                            $this->trustedLists[$newTSL->getSchemeOperatorName()] = $newTSL;
                        };
                    };
                }
            }
        };
        if ($tslPointer) {
            foreach ($tslPointer->ServiceDigitalIdentities as $digitalId) {
                $this->digitalIdentities[] = new ServiceDigitalIdentity($digitalId);
            };
            $this->TSLLocation = (string)$tslPointer->TSLLocation;
        }
    }

    private function getTSL($TSLPointer)
    {
        foreach ($TSLPointer->AdditionalInformation->OtherInformation as $OtherInfo) {
            if (strpos($OtherInfo->asXML(), '<ns3:MimeType>')) {
                if (
                    explode("<", explode(">", $OtherInfo->asXML())[2])[0] ==
                    'application/vnd.etsi.tsl+xml'
                ) {
                    $TSLLocation = (string)$TSLPointer->TSLLocation;
                    $TSLXML = DataSource::getDataFile($TSLLocation);
                    $newTL = new TrustedList($TSLXML, $TSLPointer);
                    return $newTL;
                }
            };
        };
        return null;
    }

    public function getX509Certificates()
    {
        $certificates = [];
        foreach ($this->digitalIdentities as $digitalIdentity) {
            foreach ($digitalIdentity->getX509Certificates() as $certificate) {
                $certificates[] = $certificate;
            }
        };
        return $certificates;
    }

    public function displayName()
    {
        return $this->schemeTerritory . ": " . $this->schemeOperatorName .
        " (" . $this->TSLFormat . " " . $this->TSLLocation . ")" . PHP_EOL;
    }

    public function getSchemeTerritory()
    {
        return $this->schemeTerritory;
    }

    public function getSchemeOperatorName()
    {
        return $this->schemeOperatorName;
    }

    public function isTLOL()
    {
        return $this->isTLOL;
    }

    public function getListIssueDateTime()
    {
        return $this->listIssueDateTime;
    }

    public function getNextUpdate()
    {
        return $this->nextUpdate;
    }

    public function TrustedLists()
    {
        return $this->trustedLists;
    }

    public function getTrustedListURL()
    {
        return $this->TSLLocation;
    }
}
