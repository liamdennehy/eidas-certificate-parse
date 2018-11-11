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
    private $serviceDigitalIdentities = [];
    private $TSPs = [];
    private $xml;
    private $verified;
    private $signedBy;
    private $verbose;
    private $tl;
    private $distributionPoints = [];

    /**
     * [__construct description]
     * @param [string]  $tlxml      [description]
     * @param [SimpleXMLElement]  $tslPointer [description]
     * @param boolean $verbose    [description]
     */
    public function __construct($tlxml, $tslPointer = null, $verbose = false)
    {
        $this->verbose = $verbose;
        $this->xml = $tlxml;
        $this->tl = new SimpleXMLElement($this->xml);
        $this->processTLAttributes();
        if ($this->verbose) {
            if (!$this->isTLOL) {
                print '  ';
            };
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
                    $this->processTLOLPointer($TLOLPointer);
                };
            }
        };
        if ($tslPointer) {
            foreach ($tslPointer->ServiceDigitalIdentities->ServiceDigitalIdentity as $SDI) {
                $this->serviceDigitalIdentities[] = new ServiceDigitalIdentity($SDI);
            };
            $this->TSLLocation = (string)$tslPointer->TSLLocation;
        };
        // if ((! $this->verified) && (! $this->isTLOL())&& $this->verifyTSL()) {
        //     $this->parseTSPs($this->tl->TrustServiceProviderList);
        // }
    }

    /**
     * [processTLOL description]
     * @param  SimpleXMLElement $otherTSLPointer [description]
     * @return [type]                  [description]
     */
    private function processTLOLPointer($otherTSLPointer)
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
        foreach ($otherTSLPointer->ServiceDigitalIdentities->ServiceDigitalIdentity as $digitalId) {
            $this->serviceDigitalIdentities[] = new ServiceDigitalIdentity($digitalId);
        };
        // if (! $this->verified) {
        //     $this->verifyTSL();
        // };
        $this->TSLLocation = (string)$otherTSLPointer->TSLLocation;
    }

    /**
     * [processTLAttributes description]
     */
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
        if (isset($this->tl->SchemeInformation->DistributionPoints->URI)) {
            foreach ($this->tl->SchemeInformation->DistributionPoints->URI as $uri) {
                $this->distributionPoints[] = (string)$uri;
            };
        };
    }

    /**
     * [parseTSPs description]
     * @param  SimpleXMLElement $tspList [description]
     */
    private function parseTSPs($tspList)
    {
        if ($tspList->TrustServiceProvider) {
            foreach ($tspList->TrustServiceProvider as $tsp) {
                $newTSP = new TrustServiceProvider($tsp, $this->verbose);
                if ($newTSP) {
                    $this->TSPs[$newTSP->getName()] = $newTSP;
                    if ($this->verbose) {
                        foreach ($newTSP->getTSPServices() as $newService) {
                            print '      ' .
                        date(DATE_RFC850, $newService->getDate()) . ': ' .
                        $newService->getType() . ' is ' .
                        $newService->getStatus() .
                        PHP_EOL;
                        }
                    }
                }
            }
        };
    }

    /**
     * [getTSL description]
     * @param  SimpleXMLElement $TSLPointer [description]
     * @return TrustedList|null             [description]
     */
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

    /**
     * [verifyTSL description]
     * @param  resource|resource[]|string|string[] $tlCerts [description]
     * @return boolean [description]
     */
    public function verifyTSL($certificates = null)
    {
        if (is_null($certificates)) {
            if (! sizeof($this->getTLX509Certificates())) {
                throw new SignatureException(
                    "No known certificates for TrustedList " .
                    $this->getName(), 1);
            }
            $certificates = $this->getTLX509Certificates();
        };
        if (! is_array($certificates)) {
            $certificates = [$certificates];
        };
        // var_dump($certificates); exit;
        foreach ($certificates as $key => $value) {
            $expectedCerts[] = X509Certificate::emit($value);
        };
        $xmlSig = new XMLSig($this->xml, $expectedCerts);
        if ($xmlSig->verifySignature()) {
            $this->verified = true;
            $this->signedBy = $xmlSig->getSignedBy();
            DataSource::persist($this->xml, $this->TSLLocation);
            return $this->verified;
        };
        $this->verified = false;
        return $this->verified;
    }

    public function processTrustedListPointers($schemeTerritory)
    {
        if ($this->isTLOL()) {
            if (
                (string)$otherTSLPointer
                  ->AdditionalInformation
                    ->OtherInformation[0]
                      ->TSLType
                != self::TLOLType
            ) {
                foreach (
                    $this->tl->SchemeInformation->PointersToOtherTSL->OtherTSLPointer
                    as $tslPointer
                ) {
                    $newTSL = $this->getTSL($tslPointer, $this->verbose);
                    if ($newTSL) {
                        $this->trustedLists[$newTSL->getSchemeOperatorName()] = $newTSL;
                    };
                }
            }
        }
    }
    /**
     * [getSignedBy description]
     * @return string Hash of signing certificate
     */
    public function getSignedBy()
    {
        return $this->signedBy;
    }

    /**
     * [getTLX509Certificates description]
     * @return array [description]
     */
    public function getTLX509Certificates()
    {
        $x509Certificates = [];
        foreach ($this->serviceDigitalIdentities as $serviceDigitalIdentity) {
            foreach ($serviceDigitalIdentity->getX509Certificates() as $x509Certificate) {
                $x509Certificates[] = $x509Certificate;
            };
        };
        return $x509Certificates;
    }

    /**
     * [getTSPs description]
     * @return TrustServiceProvider[] [description]
     */
    public function getTSPs()
    {
        return $this->TSPs;
    }

    public function getTSPServices()
    {
        if (! $this->isTLOL()) {
            foreach ($this->getTSPs() as $tsp) {
                foreach ($tsp->getTSPServices() as $tspService) {
                    $tspServices
                        [$this->schemeTerritory]
                            [$tsp->getName()]
                                [$tspService->getName()]
                                    = $tspService;
                }
            };
            return $tspServices;
        } else {
            foreach ($this->getTrustedLists() as $tl) {
                var_dump($tl);
            }
        }
        return $this->TSPs;
    }

    /**
     * [displayName description]
     * @return string [description]
     */
    public function getName()
    {
        return $this->schemeTerritory . ": " . $this->schemeOperatorName;
    }

    /**
     * [getSchemeTerritory description]
     * @return string [description]
     */
    public function getSchemeTerritory()
    {
        return $this->schemeTerritory;
    }

    /**
     * [getSchemeOperatorName description]
     * @return string [description]
     */
    public function getSchemeOperatorName()
    {
        return $this->schemeOperatorName;
    }

    /**
     * [isTLOL description]
     * @return boolean [description]
     */
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

    /**
     * [getTrustedLists description]
     * @return TrustedList[] [description]
     */
    public function getTrustedLists()
    {
        return $this->trustedLists;
    }

    /**
     * [getDistributionPoints description]
     * @return string[] [description]
     */
    public function getDistributionPoints()
    {
        return $this->distributionPoints;
    }

    /**
     * [getTSLLocation description]
     * @return string [description]
     */
    public function getTSLLocation()
    {
        return $this->TSLLocation;
    }
}
