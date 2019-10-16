<?php

namespace eIDASCertificate\TSPService;

/**
 *
 */
class QualificationElement
{
    private $qualifierURIs = [];

    /**
     * [__construct description]
     * @param SimpleXMLElement $qualifications [description]
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
                $assert = (string)$criteriaList->attributes()['assert'];
                foreach ($criteriaList->children('ns5', true) as $key => $criteria) {
                    switch ($key) {
                    case 'PolicySet':
                      foreach ($criteria->children('ns5', true) as $key => $policyIdentifier) {
                          switch ($key) {
                          case 'PolicyIdentifier':
                            // code...
                            break;

                          default:
                            throw new \Exception("Unrecognised PolicySet element '$key'", 1);
                            break;
                        }
                      }
                      break;

                    case 'Description':
                      var_dump((string)$criteria);
                      break;
                    case 'CriteriaList':
                      var_dump($criteria->asXML());
                      break;

                    default:
                      throw new \Exception("Unrecognised CriteriaList element '$key'", 1);

                      break;
                  }
                    // var_dump([$key,$value]);
                }
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
