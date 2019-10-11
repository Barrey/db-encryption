<?php

require __DIR__.'/vendor/autoload.php';

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
        $ssn = (new EncryptedField($engine, 'contacts', 'ssn'))
        // Add a blind index for the "last 4 of SSN":
        ->addBlindIndex(
            new BlindIndex(
                // Name (used in key splitting):
                'contact_ssn_last_four',
                // List of Transforms: 
                [new LastFourDigits()],
                // Bloom filter size (bits)
                32
            )
        )
        // Add a blind index for the full SSN:
        ->addBlindIndex(
            new BlindIndex(
                'contact_ssn', 
                [],
                32
            )
        );

        // Some example parameters:
        $contactInfo = [
            [
                'name' => 'John Smith',
                'ssn' => '123-45-6789',
                'email' => 'foo@example.org123.id'
            ],
            [
                'name' => 'Bambang Alexandria',
                'ssn' => '123-45-6789',
                'email' => 'bambang@alexa.com'
            ],
        ];

        // var_dump($ssn->prepareForStorage($contactInfo['ssn']));
        $ssn->setTypedIndexes(true);
        foreach($contactInfo as $data){
            var_dump($ssn->prepareForStorage($data['email']));
        }
    
    //Search encrypted
        $indexes = $ssn->getAllBlindIndexes('123-45-6789');
        $lastFour = $ssn->getBlindIndex('123-45-sss67389', 'contact_ssn_last_four');

        // var_dump($indexes);     //bisa dipake acuan buat search, cek nilai contact_ssn['value']
        // var_dump($lastFour);    //jangan dipake acuan buat search, ternyata bisa. dengan bit yg lebih besar (32)
    //Decrypt
        



