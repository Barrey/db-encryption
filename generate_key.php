<?php

require __DIR__.'/vendor/autoload.php';

use ParagonIE\ConstantTime\Hex;

var_dump(Hex::encode(random_bytes(32)));
