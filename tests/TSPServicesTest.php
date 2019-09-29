<?php

namespace eIDASCertificate\tests;

use PHPUnit\Framework\TestCase;
use eIDASCertificate\DataSource;
use eIDASCertificate\TrustedList;
use eIDASCertificate\TSPService;
use eIDASCertificate\Certificate\X509Certificate;
use eIDASCertificate\ParseException;
use eIDASCertificate\SignatureException;
use eIDASCertificate\CertificateException;
use eIDASCertificate\TrustedListException;

class TSPServicesTest extends TestCase
{
    const lotlXMLFileName = 'eu-lotl.xml';
    const TSPServiceCertHash = 'a7ffad289ed36fbba729621207504a8055614a5551ae2d580870326985b2ef9d';
    const TSPServicePEM = '-----BEGIN CERTIFICATE-----
MIIFnTCCA4WgAwIBAgIBDDANBgkqhkiG9w0BAQsFADBNMQswCQYDVQQGEwJOTDEZ
MBcGA1UECgwQRGlnaWRlbnRpdHkgQi5WLjEjMCEGA1UEAwwaRGlnaWRlbnRpdHkg
QnVyZ2VyIENBIC0gRzIwHhcNMTEwNTAzMTYyMTI1WhcNMjAwMzIzMTAyOTQ2WjBL
MQswCQYDVQQGEwJOTDEZMBcGA1UEChMQRGlnaWRlbnRpdHkgQi5WLjEhMB8GA1UE
AxMYRGlnaWRlbnRpdHkgU1NDRCBDQSAtIEcyMIICIjANBgkqhkiG9w0BAQEFAAOC
Ag8AMIICCgKCAgEApzzXxT6mDXgGUvpP9XQvtwyZFvOJCHDhbBzrIEU5HzH+rmrq
fMolxkoNIfw4WMQPGjfZMJ27hc96dbeFKsPzaBOZIzvVksi4aPyrNgcFqHAF3I76
bTsQfo5FO/HVI1oySO8UW0dcFYCVUMCerHenAxltUx3H0hAiXjSU7D6NPSbI+hXX
uCB4mPbzwLXcRudKA78O1Je+MolO4RvUirgZiMD9AQfXgHEeO9UVRVDPnuSrwUMn
VOrLSMVJxBMr0u1GwznasPiogbw9qAXQxlGEf+wA4lA5SWAZxj6WZ4r+usm0Q+fc
bXsxYZzCTBRa20lovEPGFWmZRqPeJcs8KI3g9UzeE2I9nYGISv9mOSCOdAOdLIoh
R9MFvMzPUo6eJ5DkeL+S//0ZSIqPU7KM4dXJ1McHfuLFblxhHTdd/0qvlltWGQ70
I3P12u7GInIw3C4XxNPKGPhTyAX+cL0Wrdam7caJOuIFSzz5R+XjTUN07eOYdzd4
yJtv/+oeI/QWHQAG/63q8KelcCuBYRVOnH48BXz5FHLAo3WVOWQEo8VtjHQwNEfl
7kkkaiMEWq9hRpcda2O08IZGsxaDAV4gZx2F2QrvEM4b+A4BqDwTMtJ+ZoPn++CH
mZwWAVBqf1MiOiO+7BVDDwsUwkL6ZOTe4McUwSMbNHE8raIRVGwkzVfYYlUCAwEA
AaOBiTCBhjAdBgNVHQ4EFgQUnANA8Q6eDO6E563JCATnnDy0o6YwDwYDVR0TAQH/
BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAQYwRAYDVR0gBD0wOzA5BgRVHSAAMDEwLwYI
KwYBBQUHAgEWI2h0dHA6Ly9wa2kuZGlnaWRlbnRpdHkuZXUvdmFsaWRhdGllMA0G
CSqGSIb3DQEBCwUAA4ICAQCZTxGoUc5DlYjP4rFwicISDbl7M1ueEidot7o+lMD3
Z9qwsy4JvpXGMQim/W9Y09nXUGo/nEaMslqQJcNgjnWXb6it+sTFB7xB4u6XJoyK
PLIz29lSI75S+fS4nYXcdNZo3NCq0RPKA1/EXU1G6FBoU8873xUDohDVvFOr/woq
08boqbl+DMJQ1ZlzurQ2FhE39be5o0obm2KcdospeCeEaP4bFC3jnKknv1UfUi6e
dnAGNHfZAa+J1R8wWHQAZBteqs6PJyRfg/jVD8w05weRjDbU7Ih8wLAmi09rZYXV
qhPKuzDHa5uzxs5JjkuqfhDJt5NeYbhCYmkIB/asA3eMSD16tvTu6UCQx+TYCbZP
/D+XetwO2DuE7FskTRdZ9U7ekUUs5/ip/EFgm4zg6MOPAI9ACUGIV8EqUmQp1f1G
ScdxFaTEM+eOs8GJzMpYVBNdsiy9NuiPfdHuUEnvDBkLRrEuEQb7O6/X6Xw8q6d+
rpeDDfdP2zKL373q0aBgZMdw+KUT1rGpT9Mosc15oWrZV+5yMnbLXT9TtaPuWUH9
FdqF14SACyobkMfkxZQ85ecQArT0y8uODxKAvX44jvyA0CxxKJ1z0DyFIsvakjud
hygdgOgkyYgEwZv6VGfrjOn5ZlhhmR8wDrRudOnWTwqVziKFkUeLDU4maruFMlbQ
IA==
-----END CERTIFICATE-----
';

    private $lotlxml;
    private $lotl;
    private $datadir;

    public function setUp()
    {
        $this->datadir = __DIR__ . '/../data';
        $xmlFilePath = $this->datadir.'/'.self::lotlXMLFileName;
        if (! file_exists($xmlFilePath)) {
            $this->lotlXML = DataSource::getHTTP(
                TrustedList::ListOfTrustedListsXMLPath
            );
            file_put_contents($xmlFilePath, $this->lotlXML);
        } else {
            $this->lotlXML = file_get_contents($xmlFilePath);
        }
        $this->lotl = new TrustedList($this->lotlXML);
    }

    public static function getTSPServicesAttributes()
    {
        $attributes = [
          'TSP' =>  TSPTest::getTSPAttributes(),
          'Name' => 'Digidentity SSCD CA - G2',
          'Type' => 'CA/QC',
          'Status' => 'granted',
          'IsActive' => true,
          'IsQualified' => true,
          'StatusStartingTime' => 1467324000,
          'Certificates' => [
            self::TSPServiceCertHash => self::TSPServicePEM
          ],
          'SKI' => 'nANA8Q6eDO6E563JCATnnDy0o6Y=',
          'SubjectName' => '/C=NL/O=Digidentity B.V./CN=Digidentity SSCD CA - G2',
          'ServiceHistory' => [
            [1304439660, 'accredited']
          ]
        ];
        return $attributes;
    }

    public function testGetTSPServices()
    {
        $lotl = $this->lotl;
        $crtFileName = $this->datadir.'/'.LOTLRootTest::lotlSigningCertPath;
        $crt = file_get_contents($crtFileName);
        $rightCert = new X509Certificate(file_get_contents($crtFileName));
        $lotl->verifyTSL($rightCert);
        $nlFile = $this->datadir.'/tl-52f7b34b484ce888c5f1d277bcb2bfbff0b1d3bbf11217a44090fab4b6a83fd3.xml';
        $this->lotl->addTrustedListXML("NL: Radiocommunications Agency", file_get_contents($nlFile));
        $nltl = $lotl->getTrustedLists()["NL: Radiocommunications Agency"];
        $tspServices = $lotl->getTSPServices(true);
        $this->assertEquals(
            8,
            sizeof($nltl->getTSPs()['CIBG']->getTSPServices())
        );
        $refAttributes = self::getTSPServicesAttributes();
        $testAttributes = $tspServices['Digidentity SSCD CA - G2'];
        $this->assertArrayHasKey(
            'TSLSignatureVerifiedAt',
            $testAttributes['TSP']['TrustedList']
        );
        $this->assertArrayHasKey(
            'TSLSignatureVerifiedAt',
            $testAttributes['TSP']['TrustedList']['ParentTSL']
        );
        unset($testAttributes['TSP']['TrustedList']['TSLSignatureVerifiedAt']);
        unset($testAttributes['TSP']['TrustedList']['ParentTSL']['TSLSignatureVerifiedAt']);
        $this->assertEquals(
            $refAttributes,
            $testAttributes
        );
        $this->assertTrue(is_array($tspServices));
        $this->assertGreaterThan(0, sizeof($tspServices));
    }
}
