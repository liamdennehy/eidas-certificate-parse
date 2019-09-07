<?php

namespace eIDASCertificate\QCStatements;

/**
 *
 */
 interface QCStatementInterface
 {
     public function getType();
     public function getDescription();
     public function getURI();
 }
