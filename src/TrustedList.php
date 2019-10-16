<?php

namespace eIDASCertificate;

use SimpleXMLElement;
use eIDASCertificate\Signature\XMLSig;
use eIDASCertificate\Certificate\X509Certificate;
use eIDASCertificate\AttributeInterface;
use DateTime;

/**
 *
 */
class TrustedList implements AttributeInterface
{
    const ListOfTrustedListsXMLPath =
      'https://ec.europa.eu/tools/lotl/eu-lotl.xml';
    const TLOLType = 'http://uri.etsi.org/TrstSvc/TrustedList/TSLType/EUlistofthelists';
    const TSLType = 'http://uri.etsi.org/TrstSvc/TrustedList/TSLType/EUgeneric';

    private $schemeOperatorName;
    private $schemeTerritory;
    private $address;
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
    private $verifiedAt;
    private $signedBy;
    private $signedByHash;
    private $tl;
    private $xmlHash;
    private $distributionPoints = [];
    private $tslPointers = [];
    private $tlPointer;
    private $tolerateFailedTLs = false;
    private $parentTSLAttributes;

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
                    $newTSP = new TrustServiceProvider($tsp, $this);
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
        if (! is_array($certificates)) {
            $certificates = [$certificates];
        };
        $pems = [];
        foreach ($certificates as $certificate) {
            $pems[($certificate->getIdentifier())] = $certificate->toPEM();
        }
        $xmlSig = new XMLSig($this->xml, $pems, $this->getName());
        try {
            $xmlSig->verifySignature();
            $this->verified = true;
            $this->verifiedAt = new DateTime('now');
            $this->signedBy = $xmlSig->getSignedBy();
            $this->signedByHash = $xmlSig->getSignedByHash();
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

    public function getSignedByHash()
    {
        return $this->signedByHash;
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
                    $x509Certificate->getIdentifier($algo)
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
        if (empty($this->TSPs)) {
            $this->parseTSPs();
        }
        $tsps = $this->TSPs;
        if ($includeChildren) {
            foreach ($this->getTrustedLists(true) as $trustedList) {
                $tsps = array_merge($tsps, $trustedList->getTSPs(false));
            }
        }
        return $tsps;
    }

    public function getTSPServices($includeChildren = false)
    {
        $tspServices = [];
        $tsps = $this->getTSPs($includeChildren);
        foreach ($tsps as $tspName => $tsp) {
            foreach ($tsp->getTSPServices() as $tspService) {
                $tspServices[$tspService->getName()] = $tspService->getAttributes();
            }
        }
        return $tspServices;
    }

    public function getTSPServicesByType($type, $includeChildren = false)
    {
        $tspServices = [];
        $tsps = $this->getTSPs($includeChildren);
        foreach ($tsps as $tsp) {
            foreach ($tsp->getTSPServices($includeChildren) as $tspService) {
                if ($tspService->getType() == $type) {
                    $tspServices[$tsp->getName()][$tspService->getName()] = $tspService;
                }
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

    public function getAddress()
    {
        if (empty($this->address)) {
            $this->address = new Address($this->tl->SchemeInformation->SchemeOperatorAddress);
        };
        return $this->address;
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
            $nextUpdate = strtotime(
                (string)$this->tl->xpath(
                    './tsl:SchemeInformation/tsl:NextUpdate/tsl:dateTime'
                )[0]
            );
            $this->nextUpdate = (new DateTime)->setTimestamp($nextUpdate);
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
    public function getTrustedLists($includeChildren = false)
    {
        $trustedLists = $this->trustedLists;
        if ($includeChildren) {
            foreach ($this->trustedLists as $trustedList) {
                array_merge($trustedLists, $trustedList->getTrustedLists($includeChildren));
            }
        }
        return $trustedLists;
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
        if (empty($this->tslPointers)) {
            $this->processTLPointers();
        };
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
            $trustedList->setParentTrustedList($this);
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
        if (empty($this->tlPointer)) {
            $this->processTLPointers();
        }
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
        if (empty($this->tslPointers)) {
            $this->processTLPointers();
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

    public function getXML()
    {
        return $this->xml;
    }

    public function getAttributes()
    {
        $tslAttributes['schemeTerritory'] = $this->getSchemeTerritory();
        $tslAttributes['schemeOperator']['name'] = $this->getSchemeOperatorName();
        $tslAttributes['sequenceNumber'] = $this->getSequenceNumber();
        $tslAttributes['issued'] = $this->getListIssueDateTime()->format('U');
        $tslAttributes['nextUpdate'] = $this->getNextUpdate()->format('U');
        $tslAttributes['sourceURI'] = $this->getTSLLocation();
        $tslAttributes['fileHash'] = hash('sha256', $this->xml);

        if (!empty($this->getSignedBy())) {
            $tslAttributes['signature']['signerThumbprint'] = $this->getSignedBy()->getIdentifier();
        } elseif (!empty($this->getSignedByHash())) {
            $tslAttributes['signature']['signerThumbprint'] = $this->getSignedByHash();
        }
        if (!empty($this->verifiedAt)) {
            $tslAttributes['signature']['verifiedAt'] = $this->verifiedAt->format('U');
        }
        if (! empty($this->getParentTrustedListAtrributes())) {
            $tslAttributes['parentTSL'] = $this->getParentTrustedListAtrributes();
        }
        $address = $this->getAddress();
        $postalAddresses = $address->getPostalAddresses();
        if (!empty($address->getPostalAddresses())) {
            $tslAttributes['schemeOperator']['postalAddresses'] = $postalAddresses;
        }
        $electronicAddresses = $address->getElectronicAddresses();
        if (!empty($address->getElectronicAddresses())) {
            $tslAttributes['schemeOperator']['electronicAddresses'] = $electronicAddresses;
        }
        return $tslAttributes;
    }

    public function setParentTrustedList(TrustedList $parentTSL)
    {
        $this->parentTSLAttributes = $parentTSL->getAttributes();
    }


    public function getParentTrustedListAtrributes()
    {
        return $this->parentTSLAttributes;
    }
}
