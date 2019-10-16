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
          switch ($type) {
            case 'PostalAddresses':
            // var_dump($addressTypeCollection->attributes());
              foreach ($addressTypeCollection as $postalAddress) {
                // $postalAddress = [];
                foreach ($postalAddress as $key => $value) {
                  $thispostalAddress[$key] = (string)$value;
                }
                // var_dump($thispostalAddress);
              }
              break;

            default:
              // throw new ParseException("Unrecognised Address type '$type'", 1);

              break;
          }
        }
    }

}
