<?php

$finder = PhpCsFixer\Finder::create()
    ->in(__DIR__ . "/src")
    ->in(__DIR__ . "/tests")
    ->in(__DIR__ . "/tools");

return PhpCsFixer\Config::create()
    ->setRules([
        '@PSR2' => true,
    ])
    ->setFinder($finder)
;
