<?php

namespace eIDASCertificate\Signature;

/**
 *
 */
class SignatureException extends \Exception
{
    private $out;

    public function __construct($message, $out)
    {
        $this->out = $out;
        parent::__construct($message);
    }

    public function getOut()
    {
        return $this->out;
    }
}
