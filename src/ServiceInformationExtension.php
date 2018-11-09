<?php

namespace eIDASCertificate;

/**
 *
 */
class ServiceInformationExtension
{
    private $type;
    private $isQualified;
    public function __construct($identifier)
    {
        $uri = (string)$identifier->AdditionalServiceInformation->URI;
        switch ($uri) {
          case '':
            // No Info provided
            // Apparently: https://stackoverflow.com/questions/27742595/php-best-way-to-stop-constructor
            throw new SafeException("No Additional Service Information", 1);

          case 'http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/ForeSeals':
            $this->type = 'ForeSeals';
            break;
          case 'http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/ForeSignatures':
            $this->type = 'ForeSignatures';
            break;
          default:
            throw new ParseException("Unknown Service Information Extension Identifier '$uri'", 1);

            break;
        };
    }

    public function getType()
    {
        // return $this->type;
    }

    public function IsQualified()
    {
        // return $this->isQualified;
    }
}
