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
    private $tolerateFailedTLs = false;

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
            $this->tl->registerXPathNamespace("tsl","http://uri.etsi.org/02231/v2#");
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
                $newTSLPointer = new TrustedList\TSLPointer($otherTSLPointer);
                switch ($tslType) {
                    case self::TSLType:
                        $this->tslPointers
                            [$newTSLPointer->getTSLFileType()]
                                [$newTSLPointer->getName()]
                                    = $newTSLPointer;
                        break;
                    case self::TLOLType:
                        $this->tlPointer = $newTSLPointer;
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
        // $this->schemeTerritory = (string)$this->tl->SchemeInformation->SchemeTerritory;
        $this->schemeTerritory = (string)$this->tl->xpath('./tsl:SchemeInformation/tsl:SchemeTerritory')[0];
        $this->schemeOperatorName = (string)$this->tl->xpath(
                "./tsl:SchemeInformation/tsl:SchemeOperatorName/*[@xml:lang='en']"
                )[0];
        $this->TSLType = new TrustedList\TSLType(
          (string)$this->tl->xpath('./tsl:SchemeInformation/tsl:TSLType')[0]
        );
        $this->listIssueDateTime = strtotime(
            (string)$this->tl->xpath(
                './tsl:SchemeInformation/tsl:ListIssueDateTime')[0]
        );
        $this->nextUpdate = strtotime(
            (string)$this->tl->xpath(
                './tsl:SchemeInformation/tsl:NextUpdate/tsl:dateTime')[0]
        );
        foreach ($this->tl->xpath(
            './tsl:SchemeInformation/tsl:DistributionPoints/tsl:URI') as $uri) {
            $this->distributionPoints[] = (string)$uri;
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

    private function processTrustedLists($failOnMissing = true)
    {
        if (sizeof($this->getTrustedListPointers()) == 0) {
            $this->processTrustedListPointers();
        };
        foreach ($this->getTrustedListPointers('xml') as $name => $tslPointer) {
            $newTL = self::loadTrustedList($tslPointer);
            if ($this->tolerateFailedTLs == false && ! $newTL) {
                throw new \Exception("Could not process TrustedList $name", 1);
            }
            // null indicates a failed load
            $this->trustedLists[$tslPointer->getName()] = $newTL;
        }
    }

    public static function fetchTrustedList($tslPointer)
    {
        return self::newTLFromXML(DataSource::fetch($tslPointer->getTSLLocation()), $tslPointer);
    }

    public static function loadTrustedList($tslPointer)
    {
        return self::newTLFromXML(DataSource::load($tslPointer->getTSLLocation()), $tslPointer);
    }

    public static function newTLFromXML($tslXml, $tslPointer)
    {
        if (! $tslXml) {
            return null;
        } else {
            $newTL = new TrustedList($tslXml, $tslPointer);
            return $newTL;
        }
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
            DataSource::persist(
                $this->xml,
                $this->getTSLLocation(),
                $this->getListIssueDateTime()
            );
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
            foreach ($this->getTrustedLists() as $name => $trustedList) {
                if ($trustedList) {
                    $verified = $trustedList->verifyTSL();
                };
                if (! $this->tolerateFailedTLs) {
                    if (! ($trustedList || $verified)) {
                        return false;
                    };
                };
            };
            return true;
        } else {
            throw new TrustedListException("This is not the Trusted List of Lists", 1);
        };
    }

    public function fetchAllTLs()
    {
        $this->processTrustedListPointers();
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
    public function getTLX509Certificates($algo = 'sha256', $hash = null)
    {
        $x509Certificates = [];
        foreach ($this->tlPointer->getServiceDigitalIdentities()
            as $serviceDigitalIdentity) {
            foreach ($serviceDigitalIdentity->getX509Certificates() as $x509Certificate) {
                $x509Certificates[
                    Certificate\X509Certificate::getHash($x509Certificate, $algo)
                    ] = $x509Certificate;
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
        return $this->getSchemeTerritory() . ": " . $this->getSchemeOperatorName();
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

    public function getTSLType()
    {
        return $this->TSLType;
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
        return DataSource::getHTTPModifiedTime($this->getTSLLocation());
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
        } else {
            return $this->tslPointers[$fileType];
        }
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
        return $this->tlPointer->getTSLLocation();
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
        foreach ($this->tslPointers[$fileType] as $tslPointer) {
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

    public function setTolerateFailedTLs($tolerateFailedTLs)
    {
        $this->tolerateFailedTLs = $tolerateFailedTLs;
    }

    public function getTolerateFailedTLs($tolerateFailedTLs)
    {
        return $this->tolerateFailedTLs;
    }
}
