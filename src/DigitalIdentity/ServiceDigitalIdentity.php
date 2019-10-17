<?php

namespace eIDASCertificate\DigitalIdentity;

use eIDASCertificate\ParseException;

/**
 *
 */
class ServiceDigitalIdentity
{
    private $x509Certificates = [];
    private $x509SubjectName;
    private $x509SKI;
    private $otherDigitalIds = [];

    /**
     * [__construct description]
     * @param SimpleXMLElement $serviceDigitalIdentity [description]
     * @throws TSPException
     */
    public function __construct($serviceDigitalIdentity)
    {
        // TODO: Make sure SKIs, fingerprints and certificates actually match
        $digitalIds = [];
        foreach ($serviceDigitalIdentity->children() as $digitalId) {
            $newDigitalId = DigitalId::parse($digitalId);
            if (empty($newDigitalId)) {
                continue;
            }
            switch ($newDigitalId->getType()) {
              case 'X509Certificate':
                $this->x509Certificates[$newDigitalId->getIdentifier()] = $newDigitalId;
                break;
              case 'X509SubjectName':
                if (!empty($this->x509SubjectName)) {
                    throw new \Exception("SDI already has a subject name", 1);
                }
                $this->x509SubjectName = $newDigitalId;
                break;
              case 'X509SKI':
                if (!empty($this->x509SKI)) {
                    throw new \Exception("SDI already has a Subject Key Identifier", 1);
                }
                $this->x509SKI = $newDigitalId;
                break;
              case 'OtherDigitalId':
                $this->otherDigitalIds[] = $newDigitalId;
                break;

              default:
                throw new ParseException("Unhandled SDI: ".$newDigitalId->getType(), 1);
                break;
            }
        };
    }

    /**
     * [getX509Certificates description]
     * @return array [description]
     */
    public function getX509Certificates()
    {
        return $this->x509Certificates;
    }

    /**
     * [getX509SKI description]
     * @param  string $algo [description]
     * @return [type]       [description]
     */
    public function getX509SKI()
    {
        if (! empty($this->x509SKI)) {
            return $this->x509SKI->getSKI();
        } elseif (sizeof($this->x509Certificates) > 0) {
            return current($this->x509Certificates)->getSubjectKeyIdentifier();
        } else {
            return null;
        }
    }

    public function getX509SubjectName()
    {
        if (! empty($this->x509SubjectName)) {
            return $this->x509SubjectName->getSubjectName();
        } elseif (sizeof($this->x509Certificates) > 0) {
            return  current($this->x509Certificates)->getSubjectDN();
        } else {
            return null;
        }
    }
}
