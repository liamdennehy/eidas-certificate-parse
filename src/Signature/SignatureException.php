<?php

namespace eIDASCertificate;

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
