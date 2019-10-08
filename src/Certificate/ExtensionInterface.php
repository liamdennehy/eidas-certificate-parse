<?php

namespace eIDASCertificate\Certificate;

use eIDASCertificate\Certificate\X509Certificate;

/**
 *
 */
 interface ExtensionInterface extends ParseInterface
 {
     public function __construct($extensionDER, $isCritical);
     public function getType();
     public function getDescription();
     public function getURI();
     public function getBinary();
     public function getIsCritical();
     public function setCertificate(X509Certificate $cert);
     public function getAttributes();
 }
