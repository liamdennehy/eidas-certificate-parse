<?php

namespace eIDASCertificate;

/**
 *
 */
class Finding
{
    private $component;
    private $severity;
    private $message;

    public function __construct($component, $severity, $message)
    {
        if (! \in_array($severity, ['info','warning','error','critical'])) {
            throw new \Exception("Invalid severity in finding", 1);
        }
        $this->component = $component;
        $this->severity = $severity;
        $this->message = $message;
    }

    public function getFinding()
    {
        return [
          'severity' => $this->severity,
          'component' => $this->component,
          'message' => $this->message
        ];
    }
}
