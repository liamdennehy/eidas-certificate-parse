<?php

namespace eIDASCertificate;

/**
 * [Trust Service Provider]
 */
class TSLType
{
    private $tslType;
    public function __construct(string $TSLType)
    {
        $this->tslType = $TSLType;
        return $this->getType();
    }

    public function getType()
    {
        switch ($this->tslType) {
        case 'http://uri.etsi.org/TrstSvc/TrustedList/TSLType/EUlistofthelists':
          return "TLOL";
          break;
        case 'http://uri.etsi.org/TrstSvc/TrustedList/TSLType/EUgeneric':
          return "EUTrustedList";
        default:
          throw new \Exception("Unknown TSLType", 1);

          break;
      }
    }
}
