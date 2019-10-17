<?php

namespace eIDASCertificate\TSPService;

use eIDASCertificate\ParseException;

/**
 *
 */
class CriteriaList
{
    private $description;
    private $criteriaList;
    private $keyUsage = [];

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
                      throw new ParseException("Unrecognised PolicyIdentifier element '$key'", 1);
                  }
                  foreach ($policy->children('ns3', true) as $key => $value) {
                      switch ($key) {
                      case 'Description':
                        $policyInfo['description'] = (string)$value;
                        break;
                      case 'Identifier':
                        $policyInfo['identifier'] = (string)$value;
                        break;
                      case 'DocumentationReferences':
                        foreach ($value->children('ns3', true) as $documentationReference) {
                            $policyInfo['docRefs'][] = (string)$documentationReference;
                        }
                        break;

                      default:
                        throw new ParseException("Unrecognised PolicyIdentifier element '$key'", 1);
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
            case 'KeyUsage':
              foreach ($criteria->children('ns5', true) as $key => $value) {
                  $keyUsageBitName = (string)$value->attributes()['name'];
                  if (strtolower((string)$value) == 'true') {
                      $this->keyUsage[$keyUsageBitName] = true;
                  } else {
                      $this->keyUsage[$keyUsageBitName] = false;
                  }
              }
              break;
            case 'otherCriteriaList':
              foreach ($criteria->children('ns4', true) as $criterionName => $otherCriterion) {
                  switch ($criterionName) {
                  case 'CertSubjectDNAttribute':
                    null;
                    break;

                  default:
                    throw new ParseException("Unrecognised otherCriteriaList element '$criterionName'", 1);
                    break;
                }
              }

              break;
            default:
              throw new ParseException("Unrecognised CriteriaList element '$key'", 1);
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

    public function getKeyUsage()
    {
        return $this->keyUsage;
    }

    public function getAttributes()
    {
        null;
    }
}
