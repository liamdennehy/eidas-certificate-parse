<?php

namespace eIDASCertificate;

use SimpleXMLElement;
use eIDASCertificate\Signature\XMLSig;
use eIDASCertificate\Certificate\X509Certificate;

/**
 *
 */
class TrustedList
{
    const ListOfTrustedListsXMLPath =
      'https://ec.europa.eu/tools/lotl/eu-lotl.xml';
    const TLOLType = 'http://uri.etsi.org/TrstSvc/TrustedList/TSLType/EUlistofthelists';
    const TSLType = 'http://uri.etsi.org/TrstSvc/TrustedList/TSLType/EUgeneric';

    private $schemeOperatorName;
    private $schemeTerritory;
    private $TSLFormat;
    private $versionID;
    private $sequenceNumber;
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
    private $tl;
    private $xmlHash;
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
        $this->xmlHash = hash('sha256', $tlxml);
        try {
            $this->tl = new SimpleXMLElement($tlxml);
        } catch (\Exception $e) {
            if ($tslPointer) {
                throw new ParseException("Error Processing XML for TrustedList " .
                $tslPointer->getName() . PHP_EOL .
                print_r(substr($tlxml, 0, 10), true), 1);
            }
            throw new ParseException("Error Processing XML for TrustedList", 1);
        }
        $this->tl->registerXPathNamespace("tsl", "http://uri.etsi.org/02231/v2#");
    }

    private function processTLPointers()
    {
        $this->tslPointers = [];
        foreach (
            $this->tl->xpath('./tsl:SchemeInformation/tsl:PointersToOtherTSL/tsl:OtherTSLPointer')
            as $otherTSLPointer
        ) {
            $otherTSLPointer->registerXPathNamespace("tsl", "http://uri.etsi.org/02231/v2#");
            $tslType = (string)$otherTSLPointer
              ->xpath('./tsl:AdditionalInformation/tsl:OtherInformation/tsl:TSLType')[0];
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
    }

    /**
     * [parseTSPs description]
     * @param  SimpleXMLElement $tspList [description]
     */
    private function parseTSPs()
    {
        if (sizeof($this->TSPs) == 0) {
            $tspList  = $this->tl->TrustServiceProviderList;
            if ($tspList->TrustServiceProvider) {
                foreach ($tspList->TrustServiceProvider as $tsp) {
                    $newTSP = new TrustServiceProvider($tsp);
                    if ($newTSP) {
                        $this->TSPs[$newTSP->getName()] = $newTSP;
                    }
                }
            }
        }
    }

    private function processTrustedLists()
    {
        if (sizeof($this->getTrustedListPointers()) == 0) {
            $this->processTLPointers();
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

    public static function loadFromPointer($tslPointer)
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
    public function verifyTSL($certificates)
    {
        // if (empty($certificates)) {
        //     $certificates = [];
        // } elseif (! is_array($certificates)) {
        if (! is_array($certificates)) {
            $certificates = [$certificates];
        };
        $pems = [];
        foreach ($certificates as $certificate) {
            $pems[($certificate->getHash())] = $certificate->toPEM();
        }
        $xmlSig = new XMLSig($this->xml, $pems, $this->getName());
        try {
            $xmlSig->verifySignature();
            $this->verified = true;
            $this->signedBy = $xmlSig->getSignedBy();
            // unset($this->xml);
        } catch (SignatureException $e) {
            $this->verified = false;
            throw $e;
        }
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
                throw new TrustedListException(
                    "No TrustedLists provided",
                    1
                );

                // $this->processTrustedLists();
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
        $this->processTLPointers();
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
        if ($this->isTLOL() && ! $this->tlPointer) {
            $this->processTLPointers();
        };
        $x509Certificates = [];
        foreach ($this->tlPointer->getServiceDigitalIdentities()
            as $serviceDigitalIdentity) {
            foreach ($serviceDigitalIdentity->getX509Certificates() as $x509Certificate) {
                $x509Certificates[
                    $x509Certificate->getHash($algo)
                    ] = $x509Certificate;
            };
        };
        return $x509Certificates;
    }

    /**
     * [getTSPs description]
     * @return TrustServiceProvider[] [description]
     */
    public function getTSPs($includeChildren = false)
    {
        $tsps = [];
        if ($includeChildren && ! empty($this->trustedLists)) {
            foreach ($this->getTrustedLists() as  $trustedList) {
                foreach ($trustedList->getTSPs(true) as $tsp) {
                    $tsps[] = $tsp;
                }
            }
            return $tsps;
        }
        if (! $this->TSPs) {
            $this->parseTSPs();
        }
        return $this->TSPs;
    }

    public function getTSPServices($includeChildren = false)
    {
        $tspServices = [];
        $tsps = $this->getTSPs($includeChildren);
        foreach ($tsps as $tsp) {
            foreach ($tsp->getTSPServices() as $tspService) {
                $tspServices[$tsp->getName()][$tspService->getName()] = $tspService;
                // code...
            }
        }
        return $tspServices;
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
        if (! $this->schemeTerritory) {
            $this->schemeTerritory = (string)$this->tl->xpath(
                './tsl:SchemeInformation/tsl:SchemeTerritory'
            )[0];
        }
        return $this->schemeTerritory;
    }

    /**
     * [getSchemeOperatorName description]
     * @return string [description]
     */
    public function getSchemeOperatorName()
    {
        if (! $this->schemeOperatorName) {
            $this->schemeOperatorName = (string)$this->tl->xpath(
                "./tsl:SchemeInformation/tsl:SchemeOperatorName/*[@xml:lang='en']"
            )[0];
        };
        return $this->schemeOperatorName;
    }

    /**
     * [isTLOL description]
     * @return boolean [description]
     */
    public function isTLOL()
    {
        return $this->getTSLType()->getType() == 'EUlistofthelists';
    }

    public function getTSLType()
    {
        if (! $this->TSLType) {
            $this->TSLType = new TrustedList\TSLType(
                (string)$this->tl->xpath('./tsl:SchemeInformation/tsl:TSLType')[0]
            );
        };
        return $this->TSLType;
    }

    public function getListIssueDateTime()
    {
        if (! $this->listIssueDateTime) {
            $this->listIssueDateTime = new \DateTime(
                (string)$this->tl->xpath(
                    './tsl:SchemeInformation/tsl:ListIssueDateTime'
                )[0]
            );
        };
        return $this->listIssueDateTime;
    }

    public function getListIssueElapsedSeconds()
    {
        return (
          (new \DateTime('now'))->getTimestamp() -
          $this->getListIssueDateTime()->getTimestamp()
        );
    }

    public function getNextUpdate()
    {
        if (! $this->nextUpdate) {
            $this->nextUpdate = strtotime(
                (string)$this->tl->xpath(
                    './tsl:SchemeInformation/tsl:NextUpdate/tsl:dateTime'
                )[0]
            );
        };
        return $this->nextUpdate;
    }

    public function getVersionID()
    {
        if (! $this->versionID) {
            $this->versionID = (integer)$this->tl->xpath(
                './tsl:SchemeInformation/tsl:TSLVersionIdentifier'
            )[0];
        };
        return $this->versionID;
    }

    public function getSequenceNumber()
    {
        if (! $this->sequenceNumber) {
            $this->sequenceNumber = (integer)$this->tl->xpath(
                './tsl:SchemeInformation/tsl:TSLSequenceNumber'
            )[0];
        };
        return $this->sequenceNumber;
    }

    public function getSourceModifiedTime()
    {
        return DataSource::getHTTPModifiedTime($this->getTSLLocation());
    }

    /**
     * [getTrustedLists description]
     * @return TrustedList[] [description]
     */
    public function getTrustedLists($title = null)
    {
        if (sizeof($this->trustedLists) == 0) {
            $this->processTrustedLists();
        }
        if (empty($title)) {
            return $this->trustedLists;
        } elseif (array_key_exists($title, $this->trustedLists)) {
            return $this->trustedLists[$title];
        } else {
            return false;
        }
    }

    public function getTrustedListPointers($fileType = null)
    {
        if ($this->isTLOL() && sizeof($this->tslPointers) == 0) {
            $this->processTLPointers();
        };
        if (! $fileType) {
            return $this->tslPointers;
        } else {
            return $this->tslPointers[$fileType];
        }
    }

    public function getTLPointerPaths()
    {
        $tlPointerPaths = [];
        foreach ($this->getTrustedListPointers('xml') as $title => $tslPointer) {
            $tlPointerPaths[$title]['location'] = $tslPointer->getTSLLocation();
            $tlPointerPaths[$title]['id'] = hash('sha256', $tslPointer->getTSLLocation());
        }
        return $tlPointerPaths;
    }

    public function addTrustedListXML($title, $xml)
    {
        if (! array_key_exists($title, $this->tslPointers['xml'])) {
            throw new TrustedListException("No pointer for Trusted List '".$title."'", 1);
        }
        $stlPointer = $this->tslPointers['xml'][$title];
        $certificates = [];
        foreach ($stlPointer->getServiceDigitalIdentities() as $tslDI) {
            foreach ($tslDI->getX509Certificates() as $certificate) {
                $certificates[] = $certificate;
            }
        }
        try {
            $trustedList = new TrustedList($xml, $this->tslPointers['xml'][$title]);
            $verified = $trustedList->verifyTSL($certificates);
        } catch (ParseException $e) {
            throw $e;
        }
        $this->trustedLists[$trustedList->getName()] = $trustedList;

        // ARGH!!!!
        // if ($trustedList->getName() != $title) {
        //   throw new TrustedListException(
        //     "Provided SchemeOperatorName '".
        //     $title.
        //     "' does not match TL SchemeOperatorName '".
        //     $trustedList->getName()."'", 1);
        // }
        return $trustedList->getName();
    }

    public function getTrustedListPointer($schemeTerritory)
    {
        $tslPointers = [];
        foreach ($this->getTrustedListPointers('xml') as $tslPointer) {
            if ($tslPointer->getSchemeTerritory() == $schemeTerritory) {
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
        if (! $this->distributionPoints) {
            foreach ($this->tl->xpath(
                './tsl:SchemeInformation/tsl:DistributionPoints/tsl:URI'
            ) as $uri) {
                $this->distributionPoints[] = (string)$uri;
            };
        };
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

    public function getTolerateFailedTLs()
    {
        return $this->tolerateFailedTLs;
    }

    public function getXMLHash()
    {
        return $this->xmlHash;
    }
}
