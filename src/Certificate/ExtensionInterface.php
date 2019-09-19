<?php

namespace eIDASCertificate\Certificate;

/**
 *
 */
 interface ExtensionInterface
 {
     public function getType();
     // public function getDescription();
     public function getURI();
     // public function getBinary();
 }
