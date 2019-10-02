<?php

namespace eIDASCertificate\Certificate;

/**
 *
 */
 interface ExtensionInterface extends ParseInterface
 {
     public function getType();
     public function getDescription();
     public function getURI();
     public function getBinary();
 }
