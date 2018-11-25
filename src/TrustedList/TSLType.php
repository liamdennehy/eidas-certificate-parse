<?php

namespace eIDASCertificate\TrustedList;

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
    public function __construct($TSLType)
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

    /**
     * [getType description]
     * @return string [description]
     */
    public function getType()
    {
        return $this->tslType;
    }

    /**
     * [getURI description]
     * @return string [description]
     */
    public function getURI()
    {
        return $this->uri;
    }
}
