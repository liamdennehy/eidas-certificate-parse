<?php

namespace eIDASCertificate\QCStatements;

use eIDASCertificate\ExtensionInterface;

/**
 *
 */
 interface QCStatementInterface extends ExtensionInterface
 {
     public function getType();
     public function getDescription();
     public function getURI();
     public function getBinary();
 }
