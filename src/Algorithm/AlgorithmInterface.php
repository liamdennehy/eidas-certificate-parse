<?php

namespace eIDASCertificate\Algorithm;

interface AlgorithmInterface
{
    public function getName();
    public function getCipherName();
    public function getDigestName();
    public function getOID();
    public function sign($privateKey, $data);
    public function verify($publicKey, $signature, $data);
}
