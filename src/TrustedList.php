<?php

namespace eIDASCertificate;

use SimpleXMLElement;

/**
 *
 */
class TrustedList
{
    const TrustedListOfListsXMLPath =
      'https://ec.europa.eu/information_society/policy/esignature/trusted-list/tl-mp.xml';
    const TLOLType = 'http://uri.etsi.org/TrstSvc/TrustedList/TSLType/EUlistofthelists';
    const TSLType = 'http://uri.etsi.org/TrstSvc/TrustedList/TSLType/EUgeneric';

    private $schemeOperatorName;
    private $schemeTerritory;
    private $TSLLocation;
    private $TSLFormat;
    private $TSLType;
    // private $tslPointer;
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
    private $tl;
    private $distributionPoints = [];
    private $tslPointers = [];
    private $tlPointer;

    /**
     * [__construct description]
     * @param [string]  $tlxml      [description]
     * @param [SimpleXMLElement]  $tslPointer [description]
     */
    public function __construct($tlxml, $tslPointer = null)
    {
        if ($tslPointer) {
            if ($tslPointer->getTSLFileType() != 'xml') {
                throw new ParseException("Input is not XML for TrustedList " .
                    $tslPointer->getName());
                };
            $this->tlPointer = $tslPointer;
        };
        if (! $tlxml) {
            throw new ParseException("No input XML string found for new TrustedList", 1);
        }
        $this->xml = $tlxml;
        try {
            $this->tl = new SimpleXMLElement($this->xml);
        } catch (\Exception $e) {
            if ($tslPointer) {
                throw new ParseException("Error Processing XML for TrustedList " .
                $tslPointer->getName() . PHP_EOL .
                print_r(substr($tlxml, 0, 10), true), 1);
            }
            throw new ParseException("Error Processing XML for TrustedList", 1);
        }

        $this->processTLAttributes();
        if ($this->isTLOL()) {
            $this->processTLPointers();
        }
    }

    private function processTLPointers()
    {
        if (sizeof($this->tslPointers) == 0) {
            foreach (
                $this->tl->SchemeInformation->PointersToOtherTSL->OtherTSLPointer
                as $otherTSLPointer
            ) {
                $tslType = (string)$otherTSLPointer
                  ->AdditionalInformation
                    ->OtherInformation[0]
                      ->TSLType;
                switch ($tslType) {
                    case self::TSLType:
                        $this->tslPointers[] = new TrustedList\TSLPointer($otherTSLPointer);
                        break;
                    case self::TLOLType:
                        $this->tlPointer = new TrustedList\TSLPointer($otherTSLPointer);
                        break;

                    default:
                        throw new ParseException("Unknown TSLType $tslType parsing Trusted Lists", 1);

                        break;
                }
            };
        };
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
        $this->TSLType = new TrustedList\TSLType(
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
    private function parseTSPs()
    {
        $tspList  = $this->tl->TrustServiceProviderList;
        if ($tspList->TrustServiceProvider) {
            foreach ($tspList->TrustServiceProvider as $tsp) {
                $newTSP = new TrustServiceProvider($tsp);
                if ($newTSP) {
                    $this->TSPs[$newTSP->getName()] = $newTSP;
                }
            }
        };
    }

    private function processTrustedLists()
    {
        if (sizeof($this->getTrustedListPointers() == 0)) {
            $this->processTrustedListPointers();
        };
        foreach ($this->getTrustedListPointers('xml') as $tslPointer) {
            $this->trustedLists[] = $this->loadTrustedList($tslPointer);
        }
    }

    public function fetchTrustedList($tslPointer)
    {
        $tslXml = DataSource::fetch($tslPointer->getTSLLocation());
        $newTL = new TrustedList($tslXml, $tslPointer);
        return $newTL;
    }

    public function loadTrustedList($tslPointer)
    {
        $tslXml = DataSource::load($tslPointer->getTSLLocation());
        $newTL = new TrustedList($tslXml, $tslPointer);
        return $newTL;
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
                throw new Signature\SignatureException(
                    "No known certificates for TrustedList " .
                    $this->getName(),
                    1
                );
            }
            $certificates = $this->getTLX509Certificates();
        };
        if (! is_array($certificates)) {
            $certificates = [$certificates];
        };
        $xmlSig = new Signature\XMLSig($this->xml, $certificates);
        if ($xmlSig->verifySignature()) {
            $this->verified = true;
            $this->signedBy = $xmlSig->getSignedBy();
            DataSource::persist($this->xml, $this->TSLLocation);
            return $this->verified;
        };
        $this->verified = false;
        return $this->verified;
    }

    /**
     * [verifyAllTLs description]
     * @return boolean [description]
     */
    public function verifyAllTLs()
    {
        if ($this->isTLOL()) {
            if (sizeof($this->trustedLists) == 0) {
                $this->processTrustedLists();
            };
            $verified = false;
            foreach ($this->getTrustedLists() as $trustedList) {
                $trustedList->verifyTSL();
            };
        } else {
            throw new TrustedListException("This is not the Trusted List of Lists", 1);
        };
        return true;
    }

    public function fetchAllTLs()
    {
        if ($this->isTLOL()) {
            $this->processTrustedListPointers();
        };
    }

    private function processTrustedListPointers()
    {
        if ($this->isTLOL() && sizeof($this->tslPointers) == 0) {
            foreach (
                $this->tl->SchemeInformation->PointersToOtherTSL->OtherTSLPointer
                as $otherTSLPointer
            ) {
                $this->tslPointers[] =
                    new TrustedList\TSLPointer($otherTSLPointer);
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
    public function getTLX509Certificates($hash = null)
    {
        // if ($this->isTLOL()) {
        //     $tlPointer = $this->tlPointer;
        // } else {
        //     $tlPointer = $this->tslPointer;
        // };
        $x509Certificates = [];
        foreach ($this->tlPointer->getServiceDigitalIdentities() as $serviceDigitalIdentity) {
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
        if (! $this->TSPs) {
            $this->parseTSPs();
        }
        return $this->TSPs;
    }

    public function getTSPServices()
    {
        $tspServices = [];
        if (! $this->isTLOL()) {
            foreach ($this->getTSPs() as $tsp) {
                foreach ($tsp->getTSPServices() as $tspService) {
                    $tspServices
                        [$this->schemeTerritory . ": " . $tsp->getName()]
                            [$tspService->getName()]
                                = $tspService;
                }
            };
            return $tspServices;
        };
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

    public function getSourceModifiedTime()
    {
        return DataSource::getHTTPModifiedTime($this->TSLLocation);
    }

    /**
     * [getTrustedLists description]
     * @return TrustedList[] [description]
     */
    public function getTrustedLists()
    {
        if (sizeof($this->trustedLists) == 0) {
            $this->processTrustedLists();
        }
        return $this->trustedLists;
    }

    public function getTrustedListPointers($fileType = null)
    {
        if (sizeof($this->tslPointers) == 0) {
            $this->processTrustedListPointers();
        };
        if (! $fileType) {
            return $this->tslPointers;
        };
        $tslPointers = [];
        foreach ($this->tslPointers as $tslPointer) {
            if ($tslPointer->getTSLFileType() == $fileType) {
                $tslPointers[] = $tslPointer;
            }
        };
        return $tslPointers;
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

    public function dumpTL()
    {
        $tslHash = hash('sha1', DataSource::fetch($this->getTSLLocation()));
        $lastModified = $this->getSourceModifiedTime();
        print "TrustedList:     " . $this->getName() . PHP_EOL;
        print "TSLLocation:     " . $this->getTSLLocation() . PHP_EOL;
        print "TSLLocationHash: " . hash('sha256', $this->getTSLLocation()) . PHP_EOL;
        print "TSLHash:         " . $tslHash . PHP_EOL;
        print "Published:       " . gmdate("Y-m-d H:i:s", $this->getListIssueDateTime()) . PHP_EOL;
        print "LastModified:    " . gmdate("Y-m-d H:i:s", strtotime($lastModified)) . PHP_EOL;
        print "NextUpdate:      " . gmdate("Y-m-d H:i:s", $this->getNextUpdate()) ;
        if ($this->getNextUpdate() < time('now')) {
            print "  <----- Update overdue!!!!!";
        };
        print PHP_EOL;
    }

    public function getTSLPointers($fileType = null)
    {
        if (! $this->tslPointers) {
            $this->processTSLPointers();
        };
        if (! $fileType) {
            return $this->tslPointers;
        };
        $tslPointers = [];
        foreach ($this->tslPointers as $tslPointer) {
            if ($tslPointer->getTSLFileType() == $fileType) {
                $tslPointers[] = $tslPointer;
            }
        };
        return $tslPointers;
    }

    public function dumpTSLPointers($fileType = null)
    {
        foreach ($this->getTSLPointers($fileType) as $tslPointer) {
            $tslPointers[] = $tslPointer->dumpTSLPointer();
        };
        return $tslPointers;
    }
}
