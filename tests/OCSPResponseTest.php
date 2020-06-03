<?php

namespace eIDASCertificate\tests;

use PHPUnit\Framework\TestCase;
use eIDASCertificate\OCSP\OCSPResponse;
use eIDASCertificate\OCSP\CertID;
use eIDASCertificate\OCSP\OCSPNonce;
use eIDASCertificate\OCSP\SingleResponse;
use eIDASCertificate\Extension;
use eIDASCertificate\AlgorithmIdentifier;
use ASN1\Type\UnspecifiedType;

class OCSPResponseTest extends TestCase
{
    public function testSingleResponse($value='')
    {
        $der = base64_decode(
            'MIGRMGkwDQYJYIZIAWUDBAIBBQAEIH8rAZ2qUc0r/VL03GY5OSntY3IQPhNxyjwfsMF'.
            'GO3/tBCCeUG7m5B22sH8DjnhmS0Nb+t0LOmP7J11hHhYfum6iMAIUWXcucAZpt2afsB'.
            'LFzdE8OigaCRGAABgPMjAyMDA1MzEyMDE1MDBaoBEYDzIwMjAwNjAyMjAxNTAwWg=='
        );
        $sResp = SingleResponse::fromDER($der);
        $this->assertEquals(
            base64_encode($der),
            base64_encode($sResp->getBinary())
        );
        $this->assertEquals(
            [
              'serialNumber' => '59772e700669b7669fb012c5cdd13c3a281a0911',
              'algorithmName' => 'sha-256',
              'issuerKeyHash' => '9e506ee6e41db6b07f038e78664b435bfadd0b3a63fb275d611e161fba6ea230',
              'issuerNameHash' => '7f2b019daa51cd2bfd52f4dc66393929ed6372103e1371ca3c1fb0c1463b7fed'

            ],
            $sResp->getAttributes()['certIDs']
        );
    }
    public function testOCSPResponse($value='')
    {
        $seq = OCSPResponse::fromDER(file_get_contents(__DIR__.'/ocsp/response-sha256'));
    }
}
