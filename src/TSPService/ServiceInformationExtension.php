<?php

namespace eIDASCertificate\TSPService;

use eIDASCertificate\SafeException;
use eIDASCertificate\ParseException;

/**
 *
 */
class ServiceInformationExtension
{
    private $type;
    private $isQualified;
    private $qualifiactionURIs = [];
    private $isCritical;
    private $qualifications;
    private $uri;

    /**
     * [__construct description]
     * @param SimpleXMLElement $identifier [description]
     */
    public function __construct($extension)
    {
        if ($extension->attributes()['Critical'] == 'true') {
            $this->isCritical = true;
        } else {
            $this->isCritical = false;
        };
        $qualifications = $extension->xpath('ns5:Qualifications');
        $asi = $extension->AdditionalServiceInformation;
        if (sizeof($asi) > 0) {
            $uri = (string)$asi[0]->URI;
            if (substr($uri, 0, 50) != 'http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt') {
                throw new SafeException("Non-ETSI Extensions are not supported ($uri)");
            };
            switch ($uri) {
            case '':
              throw new ParseException("No Additional Service Information", 1);
              break;
            case 'http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/ForeSeals':
              $this->type = 'ForeSeals';
              $this->uri = $uri;
              break;
            case 'http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/ForeSignatures':
              $this->type = 'ForeSignatures';
              $this->uri = $uri;
              break;
            case 'http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/ForWebSiteAuthentication':
              $this->type = 'ForWebSiteAuthentication';
              $this->uri = $uri;
              break;
            case 'http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/RootCA-QC':
              $this->type = 'RootCA-QC';
              $this->uri = $uri;
              break;
            default:
              if ($this->isCritical) {
                  throw new ParseException("Unknown Critical Service Information Extension Identifier '$uri'", 1);
              } else {
                  return null;
              }
              break;
          };
        }
        if (sizeof($qualifications) > 0) {
            $this->qualifications = new Qualifications($qualifications);
        }
    }

    public function getType()
    {
        return $this->type;
    }

    public function getURI()
    {
        return $this->uri;
    }

    public function getQualifierURIs()
    {
        if (!empty($this->qualifications)) {
            return $this->qualifications->getQualifierURIs();
        } else {
            return [];
        }
    }

    public function getKeyUsage()
    {
        if (!empty($this->qualifications)) {
            return $this->qualifications->getKeyUsage();
        } else {
            return [];
        }
    }
}
