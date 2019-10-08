<?php

namespace eIDASCertificate\Certificate;

/**
 *
 */
 interface ExtensionInterface extends ParseInterface
 {
     public function __construct($extensionDER, bool $isCritical);
     public function getType();
     public function getDescription();
     public function getURI();
     public function getBinary();
     public function getIsCritical();
     // public function setCertificate();
     public function getAttributes();
 }
