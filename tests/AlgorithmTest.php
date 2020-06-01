<?php

namespace eIDASCertificate\tests;

use PHPUnit\Framework\TestCase;
use eIDASCertificate\AlgorithmIdentifier;

class AlgorithmTest extends TestCase
{
    private $requestDER;
    private $sha1bin;
    private $sha256bin;

    public function setUp()
    {
        $this->sha1bin = base64_decode('MAkGBSsOAwIaBQA=');
        $this->sha256bin = base64_decode('MA0GCWCGSAFlAwQCAQUA');
    }

    public function testAlgorithmIdentifier()
    {
        $algo = AlgorithmIdentifier::fromDER($this->sha1bin);
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
        $algo = new AlgorithmIdentifier('sha1');
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
            base64_encode($this->sha1bin),
            base64_encode($algo->getBinary())
        );
        $algo = new AlgorithmIdentifier('sha-256');
        $this->assertEquals(
            '2.16.840.1.101.3.4.2.1',
            $algo->getAlgorithmOID()
        );
        $algo = AlgorithmIdentifier::fromDER($this->sha256bin);
        $this->assertEquals(
            'sha-256',
            $algo->getAlgorithmName()
        );
        $this->assertEquals(
            '2.16.840.1.101.3.4.2.1',
            $algo->getAlgorithmOID()
        );
        $algo = new AlgorithmIdentifier('sha256');
        $this->assertEquals(
            '2.16.840.1.101.3.4.2.1',
            $algo->getAlgorithmOID()
        );
        $algo = new AlgorithmIdentifier('2.16.840.1.101.3.4.2.1');
        $this->assertEquals(
            'sha-256',
            $algo->getAlgorithmName()
        );
        $this->assertEquals(
            [],
            $algo->getParameters()
        );
        $this->assertEquals(
            base64_encode($this->sha256bin),
            base64_encode($algo->getBinary())
        );
    }

    public function testAlgorithmIdentifierFromAlgorithmIdentifier()
    {
        $alg = new AlgorithmIdentifier('sha256');
        $algFromAlg = new AlgorithmIdentifier($alg);
        $this->assertEquals(
            base64_decode($this->sha256bin),
            base64_decode($algFromAlg->getBinary())
        );
    }

    public function testAlgorithmIdentifierWithParameters()
    {
        $b64 = 'MD0GCSqGSIb3DQEBCjAwoA0wCwYJYIZIAWUDBAIDoRowGAYJKoZIhvcNAQEIMAsGCWCGSAFlAwQCA6IDAgFA';
        $parameters = [
          'oA0wCwYJYIZIAWUDBAID',
          'oRowGAYJKoZIhvcNAQEIMAsGCWCGSAFlAwQCAw==',
          'ogMCAUA='
        ];

        $algo = AlgorithmIdentifier::fromDER(
            base64_decode($b64)
        );
        $this->assertEquals(
            'RSASSA-PSS',
            $algo->getAlgorithmName()
        );
        $this->assertEquals(
            '1.2.840.113549.1.1.10',
            $algo->getAlgorithmOID()
        );
        $this->assertEquals(
            $parameters,
            $algo->getParameters()
        );
        $this->assertEquals(
            $b64,
            base64_encode($algo->getBinary())
        );
    }
}
