<?php

require __DIR__.'/vendor/autoload.php';

use ParagonIE\CipherSweet\Backend\ModernCrypto;
use ParagonIE\CipherSweet\CipherSweet;
use ParagonIE\CipherSweet\KeyProvider\StringProvider;
use ParagonIE\CipherSweet\EncryptedField;
use ParagonIE\CipherSweet\Transformation\LastFourDigits;
use ParagonIE\CipherSweet\BlindIndex;

$provider = new StringProvider(
    // Example key, chosen randomly, hex-encoded:
    '4e1c44f87b4cdf21808762970b356891db180a9dd9850e7baf2a79ff3ab8a2fc'
);

$engine = new CipherSweet($provider);

/** @var CipherSweet $engine */
$ssn = (new EncryptedField($engine, 'contacts', 'ssn'))
    // Add a blind index for the "last 4 of SSN":
    ->addBlindIndex(
        new BlindIndex(
            // Name (used in key splitting):
            'contact_ssn_last_four',
            // List of Transforms:
            [new LastFourDigits()],
            // Bloom filter size (bits)
            16
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

$email_encrypt = (New EncryptedField($engine, 'contacts', 'email'))
                    ->addBlindIndex(
                        new BlindIndex(
                            'contact_ssn_last_four',
                            [new LastFourDigits()],
                            8
                        )
                    );


// Some example parameters:
$contactInfo = [
    'name' => 'John Smith',
    'ssn' => '123-45-6789',
    'email' => 'foo@example.com'
];

/** 
 * @var string $ciphertext
 * @var array<string, array<string, string>> $indexes
 */
list ($ciphertext, $indexes1) = $ssn->prepareForStorage($contactInfo['ssn']);
list ($cipheremail, $indexes2) = ($email_encrypt->prepareForStorage($contactInfo['email']));


echo '<pre>';
print_r($ciphertext);
echo '</pre>';
echo '<pre>';
print_r($ssn->prepareForStorage($contactInfo['email']));
echo '</pre>';
echo '<pre>';
print_r($cipheremail);
echo '<br/>';
print_r($indexes2);
echo '</pre>';
