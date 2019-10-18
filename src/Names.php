<?php

namespace eIDASCertificate;

/**
 *
 */
class Names
{
    private $names = [];

    public function __construct($names)
    {
        if (!empty($names)) {
            foreach ($names->children() as $name) {
                $this->names[] = [
              'lang' => (string)$name->attributes('xml', true),
              'name' => (string)$name
            ];
            }
        }
    }

    public function getNames()
    {
        return $this->names;
    }
}
