<?php

namespace PSD2Certificate\tests;

use PHPUnit\Framework\TestCase;;
use PSD2Certificate\Parser;

class ParserTest extends TestCase
{
    public function testHelloWorld()
    {
        $t1 = new Parser("Hello World");
        $this->assertEquals(
          'Hello World', $t1->HelloWorld());
    }

}
