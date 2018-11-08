<?php

namespace eIDASCertificate;

/**
 *
 */
class ServiceDigitalIdentity
{
  private $x509Certificate;

  public function __construct($digitalIdentity) {
    $this->x509Certificate = openssl_x509_read(
      $this->string2pem(
        (string)$digitalIdentity->DigitalId->X509Certificate
      )
    );
  }

  private function string2pem($certificateString) {
    return "-----BEGIN CERTIFICATE-----\n" .
      chunk_split($certificateString, 64, "\n") .
      "-----END CERTIFICATE-----\n";
  }
}
