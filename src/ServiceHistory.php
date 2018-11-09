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
        foreach ($history->ServiceHistoryInstance as $instance) {
            $thisinstance = new ServiceHistoryInstance($instance);
            $historyInstances[$thisinstance->getTime()] = $thisinstance;
        }
    }
}
