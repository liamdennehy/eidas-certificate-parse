<?php

namespace eIDASCertificate;

/**
 * [Trust Service Provider]
 */
class TSLType
{
    private $tslType;
    private $uri;

    /**
     * [__construct description]
     * @param string $TSLType [description]
     */
    public function __construct(string $TSLType)
    {
        $this->uri = $TSLType;
        switch ($TSLType) {
        case 'http://uri.etsi.org/TrstSvc/TrustedList/TSLType/EUlistofthelists':
          $this->tslType = "EUlistofthelists";
          break;
        case 'http://uri.etsi.org/TrstSvc/TrustedList/TSLType/EUgeneric':
          $this->tslType = "EUgeneric";
          break;
        default:
          $this->uri = null;
          throw new ParseException("Unknown Trusted List Type (TSLType) $TSLType", 1);
          break;
      };
    }

    public function getType()
    {
        return $this->tslType;
    }

    public function getURI()
    {
        return $this->uri;
    }
}
