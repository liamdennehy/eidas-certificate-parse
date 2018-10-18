<?php

namespace PSD2Certificate;

/**
 *
 */
class Parser
{

  private $hello;
  function __construct($hello)
  {
    $this->hello = $hello;
  }

  public function HelloWorld() {
    return $this->hello;
  }
}
 ?>
