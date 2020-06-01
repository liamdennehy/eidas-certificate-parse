<?php

namespace eIDASCertificate\tests;

use PHPUnit\Framework\TestCase;
use eIDASCertificate\DistinguishedName;
use ASN1\Type\UnspecifiedType;

class DNTest extends TestCase
{
    public function testParseDN()
    {
        $dnDER = base64_decode(
            'MIIBHzELMAkGA1UEBhMCUEwxFDASBgNVBAgMC21hem93aWVja2llMREwDwYDVQQHDA'.
          'hXYXJzemF3YTEjMCEGA1UECwwaQml1cm8gT3R3YXJ0ZWogQmFua293b8WbY2kxPTA7'.
          'BgNVBBAwNAwMUHXFgmF3c2thIDE1DA8wMC05NzUgV2Fyc3phd2EMC21hem93aWVja2'.
          'llDAZQb2xza2ExHjAcBgNVBGEMFVBTRFBMLVBGU0EtNTI1MDAwNzczODFEMEIGA1UE'.
          'Cgw7UG93c3plY2huYSBLYXNhIE9zemN6xJlkbm/Fm2NpIEJhbmsgUG9sc2tpIFNww7'.
          'PFgmthIEFrY3lqbmExHTAbBgNVBAMMFHNhbmRib3guYXBpLnBrb2JwLnBs'
        );
        $dn = new DistinguishedName(UnspecifiedType::fromDER($dnDER));
        $this->assertEquals(
            '/C=PL/ST=mazowieckie/L=Warszawa/OU=Biuro Otwartej '.
          'Bankowości/postalAddress=Puławska 15/postalAddress=00-975 '.
          'Warszawa/postalAddress=mazowieckie/postalAddress=Polska'.
          '/2.5.4.97=PSDPL-PFSA-5250007738/O=Powszechna Kasa Oszczędności '.
          'Bank Polski Spółka Akcyjna/CN=sandbox.api.pkobp.pl',
            $dn->getDN()
        );
        $this->assertEquals(
            $dn->getHash(),
            $dn->getHash('sha256')
        );
        $this->assertEquals(
            'baed2bb36c0b280e299784f9e65b35d2a8940ec6',
            bin2hex($dn->getHash('sha1'))
        );
        $this->assertEquals(
            '8b29f23c66f79a3cfa2e9a0b6406c9b03cd047cef57bb8abec6e01be05d259ea',
            bin2hex($dn->getHash('sha256'))
        );
    }
}
