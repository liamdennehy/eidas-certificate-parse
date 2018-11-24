<?php

namespace eIDASCertificate\TSPService;

/**
 *
 */
class ServiceHistory
{
    private $historyInstances = [];

    /**
     * [__construct description]
     * @param SimpleXMLElement $history [description]
     */
    public function __construct($history)
    {
        if ($history->ServiceHistoryInstance) {
            foreach ($history->ServiceHistoryInstance as $instance) {
                $thisinstance = new ServiceHistoryInstance($instance);
                $this->historyInstances[$thisinstance->getTime()] = $thisinstance;
            };
        };
        ksort($this->historyInstances);
    }

    public function getLastStatus()
    {
        return end($this->historyInstances);
    }

    public function getInstances()
    {
        return $this->historyInstances;
    }
}
