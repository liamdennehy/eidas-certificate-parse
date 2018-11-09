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
    private $trustedLists = [];
    private $digitalIdentities = [];
    private $TSPs = [];
    private $xml;
    private $verified;
    private $verbose;
    private $tl;

    public function __construct(string $tlxml, $tslPointer = null, $verbose = false)
    {
        $this->verbose = $verbose;
        $this->xml = $tlxml;
        $this->tl = new SimpleXMLElement($this->xml);
        $this->processTLAttributes();
        if ($this->verbose) {
            if (!$this->isTLOL) {print '  ';};
            print $this->schemeTerritory . ': ' . $this->schemeOperatorName . PHP_EOL;
        };
        if ($this->isTLOL()) {
            foreach (
                $this->tl->SchemeInformation->PointersToOtherTSL->OtherTSLPointer
                as $otherTSLPointer
            ) {
                if (
                    (string)$otherTSLPointer
                      ->AdditionalInformation
                        ->OtherInformation[0]
                          ->TSLType
                    == self::TLOLType
                ) {
                    $TLOLPointer = $otherTSLPointer;
                    $this->processTLOL($TLOLPointer);
                } else {
                    $newTSL = $this->getTSL($otherTSLPointer, $verbose);
                    if ($newTSL) {
                        $this->trustedLists[$newTSL->getSchemeOperatorName()] = $newTSL;
                        // if ($this->verbose) {
                        //     print '  ' . $newTSL->schemeTerritory . ': ' . $newTSL->schemeOperatorName . PHP_EOL;
                        // };
                    };
                }
            }
        };
        if ($tslPointer) {
            foreach ($tslPointer->ServiceDigitalIdentities as $digitalId) {
                $this->digitalIdentities[] = new ServiceDigitalIdentity($digitalId);
            };
            $this->TSLLocation = (string)$tslPointer->TSLLocation;
        };
        if ((! $this->verified) && (! $this->isTLOL())&& $this->verifyTSL()) {
            $this->parseTSPs($this->tl->TrustServiceProviderList);
        }
    }

    private function processTLOL($otherTSLPointer)
    {
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
        if (! $this->verified) {
            $this->verifyTSL();
        };
        $this->TSLLocation = (string)$otherTSLPointer->TSLLocation;
    }

    private function processTLAttributes()
    {
        $this->schemeTerritory = (string)$this->tl->SchemeInformation->SchemeTerritory;
        $this->schemeOperatorName =
          (string)$this->tl
            ->SchemeInformation
              ->SchemeOperatorName
                ->xpath("*[@xml:lang='en']")[0];
        $this->TSLType = new TSLType(
          (string)$this->tl->SchemeInformation->TSLType
        );
        $this->listIssueDateTime = strtotime(
            $this->tl->SchemeInformation->ListIssueDateTime
        );
        $this->nextUpdate = strtotime(
            $this->tl->SchemeInformation->NextUpdate->dateTime
        );
    }
    private function parseTSPs($tspList)
    {
        if ($tspList->TrustServiceProvider) {
            foreach ($tspList->TrustServiceProvider as $tsp) {
                $newTSP = new TrustServiceProvider($tsp, $this->verbose);
                if ($newTSP) {
                    $this->TSPs[$newTSP->getName()] = $newTSP;
                    if ($this->verbose) {
                        foreach ($newTSP->getServices() as $newService) {
                            print '      ' .
                        date(DATE_RFC850, $newService['startingTime']) . ': ' .
                        $newService['type'] . ' is ' . $newService['status'] .
                        PHP_EOL;
                        }
                    }
                }
            }
        };
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
                    $TSLXML = DataSource::load($TSLLocation);
                    $newTL = new TrustedList($TSLXML, $TSLPointer, $this->verbose);
                    return $newTL;
                }
            };
        };
        return null;
    }

    public function verifyTSL()
    {
        $xmlSig = new XMLSig($this->xml, $this->getX509Certificates());
        if ($xmlSig->verifySignature()) {
            $this->verified = true;
            return $this->verified;
        };
        $this->verified = false;
        return $this->verified;
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

    public function getTSPs()
    {
        return $this->TSPs;
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
        return $this->TSLType->getType() == 'EUlistofthelists';
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
