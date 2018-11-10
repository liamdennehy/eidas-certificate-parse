<?php

namespace eIDASCertificate;

/**
 *
 */
class ServiceHistory
{
    private $historyInstances = [];

    public function __construct($history)
    {
        $historyInstances = [];
        if ($history->ServiceHistoryInstance) {
            foreach ($history->ServiceHistoryInstance as $instance) {
                $thisinstance = new ServiceHistoryInstance($instance);
                $this->historyInstances[$thisinstance->getTime()] = $thisinstance;
            };
        };
        sort($this->historyInstances);
    }

    public function getLastStatus()
    {
        return end($historyInstances);
    }

    public function getInstances()
    {
        return $this->historyInstances;
    }
}
