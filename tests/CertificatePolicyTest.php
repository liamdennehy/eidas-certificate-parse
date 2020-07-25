<?php

namespace eIDASCertificate\tests;

use PHPUnit\Framework\TestCase;
use eIDASCertificate\Extension;
use eIDASCertificate\Extensions;
use eIDASCertificate\Certificate\CertificatePolicies;
use eIDASCertificate\Certificate\SubjectKeyIdentifier;
use eIDASCertificate\Certificate\BasicConstraints;
use eIDASCertificate\Certificate\CRLDistributionPoints;
use eIDASCertificate\Certificate\ExtendedKeyUsage;
use eIDASCertificate\Certificate\KeyUsage;
use eIDASCertificate\Certificate\OCSPNoCheck;
use eIDASCertificate\Certificate\PreCertPoison;
use eIDASCertificate\Certificate\SubjectAltName;
use ASN1\Type\UnspecifiedType;

class CertificatePolicyTest extends TestCase
{

  public function testUnknownCertificatePolicy()
  {
      $extensionDER = base64_decode(
          'MFEwRAYKKwYBBAG+WAGDEDA2MDQGCCsGAQUFBwIBFihodHRwOi8vd3d3LnF1b3ZhZGlzZ2xvYmFsLmNvbS9yZXBvc2l0b3J5MAkGBwQAi+xAAQM='
      );
      $CPs = new CertificatePolicies($extensionDER);
      $this->assertEquals(
          [
            'severity' => 'warning',
            'component' => 'certificatePolicies',
            'message' => 'Certificate Policy from unknown vendor as oid \'1.3.6.1.4.1.8024.1.400\': MEQGCisGAQQBvlgBgxAwNjA0BggrBgEFBQcCARYoaHR0cDovL3d3dy5xdW92YWRpc2dsb2JhbC5jb20vcmVwb3NpdG9yeQ=='
          ],
          $CPs->getFindings()[0]->getFinding()
      );
    }

    public function testEVCertificatePolicy()
    {
        $extensionDER = base64_decode(
          'MIGYMIGABgsrBgEEAeZ5CgEDCjBxMC8GCCsGAQUFBwIBFiNodHRwOi8vd3d3LmZpcm1hcHJvZmVzaW9uYWwuY29tL2NwczA+BggrBgEFBQcCAjAyDDBFc3RlIGVzIHVuIENlcnRpZmljYWRvIGRlIFNlcnZpZG9yIFdlYiBwYXJhIFBTRDIwCQYHBACL7EABBDAIBgYEAI96AQQ='
        );
        $CPs = new CertificatePolicies($extensionDER);
        $this->assertEquals(
          [
            'issuer' => [
              'policies' => [
                [
                  'oid' => '0.4.0.2042.1.4',
                  'name' => 'EVCP',
                  'description' => 'Consistent with EV Certificates Guidelines issued by the CAB Forum',
                  'url' => 'https://www.etsi.org/deliver/etsi_ts/102000_102099/102042/02.04.01_60/ts_102042v020401p.pdf#chapter-5.2',
                  'vendor' => 'ETSI'
                ],
              ]
            ]
          ],
          $CPs->getAttributes()
        );
    }

    public function testPSD2Policies()
    {
      $extensionDER = base64_decode(
        'MHYwCQYHBACL7EABBDAJBgcEAIGYJwMBMA4GDCsGAQQBvlgAAmQBAjBFBgorBgEEAb5YAYNCMDcwNQYIKwYBBQUHAgEWKWh0dHBzOi8vd3d3LnF1b3ZhZGlzZ2xvYmFsLmNvbS9yZXBvc2l0b3J5MAcGBWeBDAEB'
      );
      $CPs = new CertificatePolicies($extensionDER);
      $this->assertEquals(
        [
          'issuer' => [
            'policies' => [
              [
                'oid' => '0.4.0.19495.3.1',
                'name' => 'qcpWebPSD2',
                'description' => 'PSD2 qualified website authentication certificate',
                'url' => 'https://www.etsi.org/deliver/etsi_ts/119400_119499/119495/01.03.02_60/ts_119495v010302p.pdf#chapter-6.1',
                'vendor' => 'ETSI'
              ],
              [
                'oid' => '2.23.140.1.1',
                'name' => 'extended_validation',
                'description' => 'Certificate issued in compliance with the Extended Validation Guidelines',
                'url' => 'https://cabforum.org/object-registry/',
                'vendor' => 'CA/Browser Forum'
              ]
            ]
          ]
        ],
        $CPs->getAttributes()
      );
      $extensionDER = base64_decode(
          'MIIBUDCCATcGDysGAQQBgagYAgEBgSoCCTCCASIwJgYIKwYBBQUHAgEWGmh0dHA6Ly9jcC5lLXN6aWduby5odS9xY3BzMEQGCCsGAQUFBwICMDgMNlF1YWxpZmllZCBQU0QyIGNlcnRpZmljYXRlIGZvciB3ZWJzaXRlIGF1dGhlbnRpY2F0aW9uLjA0BggrBgEFBQcCAjAoDCZPcmdhbml6YXRpb25hbCB2YWxpZGF0aW9uIGNlcnRpZmljYXRlLjBFBggrBgEFBQcCAjA5DDdNaW7FkXPDrXRldHQgUFNEMiB3ZWJvbGRhbC1oaXRlbGVzw610xZEgdGFuw7pzw610dsOhbnkuMDUGCCsGAQUFBwICMCkMJ1N6ZXJ2ZXpldC1lbGxlbsWRcnrDtnR0IHRhbsO6c8OtdHbDoW55LjAJBgcEAIGYJwMBMAgGBmeBDAECAg=='
      );
      $CPs = new CertificatePolicies($extensionDER);
      $this->assertEquals(
        1,
        sizeof($CPs->getFindings())
      );
      $this->assertEquals(
        [
            'message' => 'Certificate Policy from unknown vendor as oid \'1.3.6.1.4.1.21528.2.1.1.170.2.9\': '.
                'MIIBNwYPKwYBBAGBqBgCAQGBKgIJMIIBIjAmBggrBgEFBQcCARYaaHR0cDovL2NwLmUtc3ppZ25vLmh1L3FjcHMwRAYIKwYBBQUHAgIwOAw2UXVhbGlmaWVkIFBTRDIgY2VydGlmaWNhdGUgZm9yIHdlYnNpdGUgYXV0aGVudGljYXRpb24uMDQGCCsGAQUFBwICMCgMJk9yZ2FuaXphdGlvbmFsIHZhbGlkYXRpb24gY2VydGlmaWNhdGUuMEUGCCsGAQUFBwICMDkMN01pbsWRc8OtdGV0dCBQU0QyIHdlYm9sZGFsLWhpdGVsZXPDrXTFkSB0YW7DunPDrXR2w6FueS4wNQYIKwYBBQUHAgIwKQwnU3plcnZlemV0LWVsbGVuxZFyesO2dHQgdGFuw7pzw610dsOhbnku',
            'severity' => 'warning',
            'component' => 'certificatePolicies'
        ],
        $CPs->getFindings()[0]->getFinding()
      );
      $this->assertEquals(
          [
          'issuer' => [
            'policies' => [
              [
                'oid' => '0.4.0.19495.3.1',
                'name' => 'qcpWebPSD2',
                'description' => 'PSD2 qualified website authentication certificate',
                'url' => 'https://www.etsi.org/deliver/etsi_ts/119400_119499/119495/01.03.02_60/ts_119495v010302p.pdf#chapter-6.1',
                'vendor' => 'ETSI'
              ],
              [
                'oid' => '2.23.140.1.2.2',
                'name' => 'organization_validation',
                'description' => 'Compliant with Baseline Requirements – Organization identity asserted',
                'url' => 'https://cabforum.org/object-registry/',
                'vendor' => 'CA/Browser Forum'
              ]
            ]
          ]
        ],
        $CPs->getAttributes()
      );

    }

    public function testMalformedCP()
    {
      $extensionDER = base64_decode(
          'MIIBCzCCAQcGB2A4CgEBAgEwgfswLAYIKwYBBQUHAgEWIGh0dHA6Ly9yZXBvc2l0b3J5LmVpZC5iZWxnaXVtLmJlMIHKBggrBgEFBQcCAjCBvRqBukdlYnJ1aWsgb25kZXJ3b3JwZW4gYWFuIGFhbnNwcmFrZWxpamtoZWlkc2JlcGVya2luZ2VuLCB6aWUgQ1BTIC0gVXNhZ2Ugc291bWlzIMOgIGRlcyBsaW1pdGF0aW9ucyBkZSByZXNwb25zYWJpbGl0w6ksIHZvaXIgQ1BTIC0gVmVyd2VuZHVuZyB1bnRlcmxpZWd0IEhhZnR1bmdzYmVzY2hyw6Rua3VuZ2VuLCBnZW3DpHNzIENQUw=='
      );
      $CPs = new CertificatePolicies($extensionDER);
      $this->assertEquals(
          [
            'severity' => 'warning',
            'component' => 'certificatePolicies',
            'message' => 'Malformed certificatePolicies extension \'Not a valid VisibleString string.\': MIIBCzCCAQcGB2A4CgEBAgEwgfswLAYIKwYBBQUHAgEWIGh0dHA6Ly9yZXBvc2l0b3J5LmVpZC5iZWxnaXVtLmJlMIHKBggrBgEFBQcCAjCBvRqBukdlYnJ1aWsgb25kZXJ3b3JwZW4gYWFuIGFhbnNwcmFrZWxpamtoZWlkc2JlcGVya2luZ2VuLCB6aWUgQ1BTIC0gVXNhZ2Ugc291bWlzIMOgIGRlcyBsaW1pdGF0aW9ucyBkZSByZXNwb25zYWJpbGl0w6ksIHZvaXIgQ1BTIC0gVmVyd2VuZHVuZyB1bnRlcmxpZWd0IEhhZnR1bmdzYmVzY2hyw6Rua3VuZ2VuLCBnZW3DpHNzIENQUw=='
          ],
          $CPs->getFindings()[0]->getFinding()
      );
    }

}
