<?php

namespace eIDASCertificate\TSPService;

/**
 *
 */
class Qualifications
{
    private $qualifierURIs = [];

    /**
     * [__construct description]
     * @param SimpleXMLElement $history [description]
     */
    public function __construct($qualifications)
    {
        if (sizeof($qualifications) > 1) {
            throw new ParseException("Multiple TSPService Qualifications", 1);
        }
        foreach ($qualifications[0]->xpath('ns5:QualificationElement') as $qualificationElement) {
            foreach ($qualificationElement->xpath('ns5:Qualifiers') as $qualifiers) {
                foreach ($qualifiers->xpath('ns5:Qualifier') as $qualifier) {
                    $this->qualifierURIs[] = (string)$qualifier->attributes()['uri'];
                }
            }
            foreach ($qualificationElement->xpath('ns5:CriteriaList') as $criteriaList) {
                // code...
            }
        }
    }

    public function getQualifierURIs()
    {
        return $this->qualifierURIs;
    }

    public function getInstances()
    {
        return $this->historyInstances;
    }
}
