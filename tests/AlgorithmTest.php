<?php

namespace eIDASCertificate\tests;

use PHPUnit\Framework\TestCase;
use eIDASCertificate\AlgorithmIdentifier;

class AlgorithmTest extends TestCase
{
    private $requestDER;

    public function testAlgorithmIdentifier()
    {
        $b64 = 'MAkGBSsOAwIaBQA=';
        $algo = AlgorithmIdentifier::fromDER(base64_decode($b64));
        $this->assertEquals(
            'sha-1',
            $algo->getAlgorithmName()
        );
        $this->assertEquals(
            '1.3.14.3.2.26',
            $algo->getAlgorithmOID()
        );
        $algo = new AlgorithmIdentifier('sha-1');
        $this->assertEquals(
            '1.3.14.3.2.26',
            $algo->getAlgorithmOID()
        );
        $algo = new AlgorithmIdentifier('1.3.14.3.2.26');
        $this->assertEquals(
            'sha-1',
            $algo->getAlgorithmName()
        );
        $this->assertEquals(
            [],
            $algo->getParameters()
        );
        $this->assertEquals(
            $b64,
            base64_encode($algo->getBinary())
        );
    }

    public function testAlgorithmIdentifierWithParameters()
    {
        $b64 = 'MD0GCSqGSIb3DQEBCjAwoA0wCwYJYIZIAWUDBAIDoRowGAYJKoZIhvcNAQEIMAsGCWCGSAFlAwQCA6IDAgFA';
        $algo = AlgorithmIdentifier::fromDER(
            base64_decode($b64)
        );
        $this->assertEquals(
            [
          'oA0wCwYJYIZIAWUDBAID',
          'oRowGAYJKoZIhvcNAQEIMAsGCWCGSAFlAwQCAw==',
          'ogMCAUA='
        ],
            $algo->getParameters()
        );
        $this->assertEquals(
            $b64,
            base64_encode($algo->getBinary())
        );
    }
}
