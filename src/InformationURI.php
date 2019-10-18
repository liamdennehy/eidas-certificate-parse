<?php

namespace eIDASCertificate;

/**
 *
 */
class InformationURI
{
    private $URIs = [];

    public function __construct($informationURI)
    {
        foreach ($informationURI->children() as $uri) {
            $this->URIs[] = [
          'lang' => (string)$uri->attributes('xml', true),
          'uri' => (string)$uri
        ];
        }
    }

    public function getInformationURIs()
    {
        return $this->URIs;
    }
}
