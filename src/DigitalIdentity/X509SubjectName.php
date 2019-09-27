<?php

namespace eIDASCertificate\DigitalIdentity;

use eIDASCertificate\Certificate\X509Certificate;

/**
 *
 */
class X509SubjectName implements DigitalIdInterface
{
    private $subjectName;

    public function __construct($value)
    {
        $this->subjectName = $value;
    }

    public function getSubjectName()
    {
        return $this->subjectName;
    }

    public function getIDentifier()
    {
        return hash('sha256',$this->getSubjectName());
    }

    public function getType()
    {
        return 'X509SubjectName';
    }
}
