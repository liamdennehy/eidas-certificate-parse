<?php

namespace eIDASCertificate\Algorithm;

use eIDASCertificate\Algorithm\AlgorithmInterface;
use eIDASCertificate\OID;
use phpseclib\Crypt\RSA;
use phpseclib\Crypt\PublicKeyLoader;

class RSAAlgorithm implements AlgorithmInterface
{
    private $algorithmIdentifier;
    private $rsa;
    const suffix = 'WithRSAEncryption';


    /**
     * @param string $digestName
     */
    public function __construct($spec, $parameters = null)
    {
        if (is_object($spec) && get_class($spec) == 'eIDASCertificate\Algorithm\AlgorithmIdentifier') {
            $this->algorithmIdentifier = $spec;
        } else {
            $this->algorithmIdentifier = new AlgorithmIdentifier($spec);
        }
        if (! empty($parameters)) {
            throw new \Exception("Cannot handle algorithms requiring parameters", 1);
        }
        $this->rsa = new RSA;
        $this->rsa->setHash(str_replace('-', '', $this->algorithmIdentifier->getDigestName()));
        $this->rsa->setSignatureMode(RSA::SIGNATURE_PKCS1);
    }

    /**
     * @return string
     */
    public function getName()
    {
        return $this->algorithmIdentifier->getName();
    }

    /**
     * @param string $key
     * @param string $data
     *
     * @return string
     */
    public function sign($signingKey, $data)
    {
        $rsa = PublicKeyLoader::load($signingKey)
          ->withHash($this->digestName)
          ->withPadding(RSA::SIGNATURE_PKCS1);
        $signature = $rsa->sign($data);

        return $signature;
    }

    public function verify($message, $signature, $verifyingKey)
    {
        // var_dump([$message, $signature, $verifyingKey]);
        $rsa = clone($this->rsa);
        $rsa->loadKey($verifyingKey);
        try {
            $valid = $rsa->verify($message, $signature);
            return $valid;
        } catch (\Exception $e) {
            if ('Invalid signature' != $e->getMessage()) {
                // Unhandled error state
                throw $e;
            } else {
                // Tolerate malformed signature
                return false;
            }
        }
    }

    public function getCipherName()
    {
        return $this->algorithmIdentifier->getCipherName();
    }

    public function getDigestName()
    {
        return $this->algorithmIdentifier->getDigestName();
    }

    public function getOID()
    {
        return $this->algorithmIdentifier->getOID();
    }
}
