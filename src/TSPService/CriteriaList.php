<?php

namespace eIDASCertificate\TSPService;

/**
 *
 */
class CriteriaList
{
    private $description;
    private $criteriaList;

    /**
     * [__construct description]
     * @param SimpleXMLElement $criteriaList [description]
     */
    public function __construct($criteriaList)
    {
        $id=hash('sha256', $criteriaList->asXML())[0];
        $assert = (string)$criteriaList->attributes()['assert'];
        $criteria = [];
        foreach ($criteriaList->children('ns5', true) as $key => $criteria) {
            switch ($key) {
            case 'PolicySet':
              foreach ($criteria->children('ns5', true) as $key => $policy) {
                  $policyInfo = [];
                  if ($key != 'PolicyIdentifier') {
                      throw new \Exception("Unrecognised PolicyIdentifier element '$key'", 1);
                  }
                  foreach ($policy->children('ns3', true) as $key => $value) {
                      switch ($key) {
                      case 'Description':
                        $policyInfo['description'] = (string)$value;
                        break;
                      case 'Identifier':
                        $policyInfo['identifier'] = (string)$value;
                        break;

                      default:
                        throw new \Exception("Unrecognised PolicyIdentifier element '$key'", 1);
                        break;
                    }
                  }
              }
              break;
            case 'Description':
              $this->description = (string)$criteria;
              break;
            case 'CriteriaList':
              $this->criteriaList = new CriteriaList($criteria);
              break;

            default:
              throw new \Exception("Unrecognised CriteriaList element '$key'", 1);
              break;
          }
        }
    }

    public function getDescription()
    {
        return $this->description;
    }

    public function getPolicyInfo()
    {
        return $this->description;
    }

    public function getAttributes()
    {
        $attrs = [];
        $attrs['description'] = $this->description;
    }
}
