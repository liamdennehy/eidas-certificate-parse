<?php

namespace eIDASCertificate\TSPService;

/**
 *
 */
class Qualifications
{
    private $qualifierURIs = [];
    private $criteriaList;

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
            $criteriaList = $qualificationElement->xpath('ns5:CriteriaList');
            if (sizeof($criteriaList) > 1) {
                throw new \Exception("Multiple CriteriaLists in TSPService Qualifications", 1);
            }
            $this->criteriaList = new CriteriaList($criteriaList[0]);
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
