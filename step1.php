<?php

require __DIR__.'/vendor/autoload.php';

/**
    todo : 
    1. encrypt
    2. search
    3. match 
*/

//File to start engine
use ParagonIE\CipherSweet\Backend\FIPSCrypto;
use ParagonIE\CipherSweet\KeyProvider\StringProvider;
use ParagonIE\CipherSweet\CipherSweet;

//File to operate
use ParagonIE\CipherSweet\BlindIndex;
use ParagonIE\CipherSweet\EncryptedField;
use ParagonIE\CipherSweet\Transformation\LastFourDigits;

//Start Engine
    //choose engine FIPSCrypto or ModernCrypto
    $fips = new FIPSCrypto(); 

    //define your key provider
    $provider = new StringProvider(
        // Example key, chosen randomly, hex-encoded:
        '299a807dac9a77d2255326f8649a54c2be583b118043d84d5b48532b7988ebda'
    );

    $engine = new CipherSweet($provider, $fips);

//Usage
    //Encrypt
    $customer_encrypt = (new EncryptedField($engine, 'contacts', 'customer_id'))
    // Add a blind index for the full SSN:
    ->addBlindIndex(
        new BlindIndex(
            'customer_id_full', 
            [],
            32
        )
    );

    // Some example parameters:
    $contactInfo = [
        [
            'customer_id' => 1,
            'name' => 'John Smith',
            'ssn' => '123-45-6789',
            'email' => 'foo@example.org.id'
        ],
        [
            'customer_id' => 2,
            'name' => 'Bambang Alexandria',
            'ssn' => '123-45-6789',
            'email' => 'bambang@alexa.com'
        ],
    ];

    $customer_encrypt->setTypedIndexes(true);
    foreach($contactInfo as $data){
        $result[] = ($customer_encrypt->prepareForStorage($data['customer_id']));
    }

    $encrypted_customer_id = [
        'fips:UgO5TH8WfjpJzjtvOqnnU9P2XLGc72CYGhec7q6M6d03fU48ml_1kul_MoRXy_M6ekop6MViyNa7WQrRevFlko6_bLikT7wti14hnpTDbf27UotoRLubwyJfxmUHOLVEWw==',
        'fips:D9k-79FrFeJoVygVcIcgkuMSFj3yOr0GkFzlr5W7KbbaYTrODknIIsoAhIMZrNZfOTbzRC7uK2dMu6zqLEeSXR6JBVYKDkVG1rdmlcEnoWUl1iptMDwryJtRcEm8s0_Alg=='
    ];

    $indexes = $customer_encrypt->getAllBlindIndexes('12');

    foreach($result as $i => $r){
        foreach($r as $ri => $rv){
            if(is_array($rv)){
                foreach($rv as $v){
                    echo '<pre>';
                    print_r($indexes['customer_id_full']);
                    print_r($v);
                    echo '</pre>';
                    print_r(array_diff($indexes['customer_id_full'], $v));
                }
            }
        }
    }


    function search($parameter){

    }