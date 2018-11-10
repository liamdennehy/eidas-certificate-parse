<?php

namespace eIDASCertificate;

/**
 *
 */
class ServiceInformationExtension
{
    private $type;
    private $isQualified;
    private $uri;
    public function __construct($identifier)
    {
        $uri = (string)$identifier->AdditionalServiceInformation->URI;
        if (substr($uri, 0, 50) != 'http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt') {
            throw new SafeException("Non-ETSI Extensions are not supported ($uri)");
        };
        switch ($uri) {
          case '':
            // No Info provided
            // Apparently: https://stackoverflow.com/questions/27742595/php-best-way-to-stop-constructor
            throw new SafeException("No Additional Service Information", 1);

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
            throw new ParseException("Unknown Service Information Extension Identifier '$uri'", 1);

            break;
        };
    }

    public function getType()
    {
        return $this->type;
    }

    public function getURI()
    {
        return $this->uri;
    }
}
