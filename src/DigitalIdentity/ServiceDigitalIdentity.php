<?php

namespace eIDASCertificate\DigitalIdentity;

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
                throw new \Exception("Unhandled SDI: ".$newDigitalId->getType(), 1);
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

    public function getX509Thumbprint()
    {
        return openssl_x509_fingerprint($this->x509Certificate);
    }

    /**
     * [getX509SKI description]
     * @param  string $algo [description]
     * @return [type]       [description]
     */
    public function getX509SKI()
    {
        if (empty($this->x509SKI) && sizeof($this->x509Certificates) > 0) {
            $this->x509SKI = base64_encode(
                current($this->x509Certificates)->getSubjectKeyIdentifier()
            );
        }
        return $this->x509SKI;
    }

    public function getX509SubjectName()
    {
        if (empty($this->x509SubjectName) && sizeof($this->x509Certificates) > 0) {
            $this->x509SubjectName =
          current($this->x509Certificates)->getSubjectName();
        }
        return $this->x509SubjectName;
    }
}
