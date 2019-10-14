<?php 

function debug($parameter){
    $result = '<pre>'.print_r($parameter);
    $result .= '<pre>';
    return $result;
}