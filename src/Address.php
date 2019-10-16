<?php

namespace eIDASCertificate;

/**
 *
 */
class Address
{
    private $postalAddresses = [];

    public function __construct($addressesCollection)
    {
        foreach ($addressesCollection->children() as $type => $addressTypeCollection) {
            // var_dump($addressTypeCollection->asXML());
            switch ($type) {
            case 'PostalAddresses':
              // var_dump($addressTypeCollection->xpath('*[@xml:lang]/@xml:lang'));
              foreach ($addressTypeCollection as $postalAddress) {
                  $lang = (string)$postalAddress->attributes('xml', true)['lang'];
                  if (array_key_exists($lang, $this->postalAddresses)) {
                      throw new ParseException("Multiple PostalAddresses in Language '$lang'", 1);
                  }
                  $thispostalAddress = [];
                  foreach ($postalAddress as $key => $value) {
                      $thispostalAddress[$key] = (string)$value;
                  }
                  $this->postalAddresses[$lang] = $thispostalAddress;
              }
              break;

            default:
              // throw new ParseException("Unrecognised Address type '$type'", 1);

              break;
          }
        }
        // var_dump($this->postalAddresses);
    }
}
