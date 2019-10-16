<?php

namespace eIDASCertificate;

/**
 *
 */
class Address
{
    private $postalAddresses = [];
    private $electronicAddresses = [];

    public function __construct($addressesCollection)
    {
        foreach ($addressesCollection->children() as $type => $addressTypeCollection) {
            switch ($type) {
            case 'PostalAddresses':
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

            case 'ElectronicAddress':
              foreach ($addressTypeCollection as $type => $electronicAddress) {
                  switch ($type) {
                  case 'URI':
                    $lang = (string)$electronicAddress->attributes('xml', true)['lang'];
                    $this->electronicAddresses[] = [
                      'lang' => $lang,
                      'uri' => (string)$electronicAddress
                    ];
                    break;

                  default:
                    throw new ParseException("Unrecognised ElectronicAddress element '$type'", 1);

                    break;
                }
              }
              break;

            default:
              throw new ParseException("Unrecognised Address type '$type'", 1);

              break;
          }
        }
    }

    public function getPostalAddresses()
    {
        return $this->postalAddresses;
    }

    public function getElectronicAddresses()
    {
        return $this->electronicAddresses;
    }
}
