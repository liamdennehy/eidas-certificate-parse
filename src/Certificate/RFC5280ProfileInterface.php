<?php

namespace eIDASCertificate\Certificate;

/**
 *
 */
 interface RFC5280ProfileInterface
 {
     public function getType();
     public function getBinary();
     public function getDates();
     public function isCurrent();
     public function isCurrentAt($dateTime);
     public function isStartedAt($dateTime = null);
     public function isNotFinishedAt($dateTime = null);
 }
