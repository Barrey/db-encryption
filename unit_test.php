<?php 

require __DIR__.'/vendor/autoload.php';
require __DIR__.'/functions.php';

use ParagonIE\CipherSweet\Backend\FIPSCrypto;
use ParagonIE\CipherSweet\Backend\ModernCrypto;
use ParagonIE\CipherSweet\CipherSweet;
use ParagonIE\CipherSweet\KeyProvider\StringProvider;
use ParagonIE\ConstantTime\Hex;
use PHPUnit\Framework\TestCase;
use ParagonIE\CipherSweet\EncryptedField;
use ParagonIE\CipherSweet\BlindIndex;
use ParagonIE\CipherSweet\Transformation\LastFourDigits;
use ParagonIE\CipherSweet\EncryptedRow;
use ParagonIE\CipherSweet\EncryptedMultiRows;
use ParagonIE\CipherSweet\Transformation\Lowercase;

/**
 * Class CipherSweetTest
 * @package ParagonIE\CipherSweet\Tests
 */
class CipherSweetTest extends TestCase
{
    /**
     * @throws \ParagonIE\CipherSweet\Exception\ArrayKeyException
     * @throws \ParagonIE\CipherSweet\Exception\CryptoOperationException
     */
    public function testBasicAPI()
    {
        $fips = new FIPSCrypto();

        $random = \random_bytes(32);
        $random = '80ecf8ede4d2c6d260d6b977b467ecd209737c7f2178dc181a44006eb98b9747';
        $provider = new StringProvider($random);

        $fipsEngine = new CipherSweet($provider, $fips);
        
        //decoded
        print_r($fipsEngine->getBlindIndexRootKey('foo', 'bar')->getRawKey());
        echo '<br/>';
        print_r($fipsEngine->getFieldSymmetricKey('foo', 'bar')->getRawKey());
        echo '<br/>';
        echo '<hr>';
        
        //encoded
        print_r(Hex::encode($fipsEngine->getBlindIndexRootKey('foo', 'bar')->getRawKey()));
        echo '<br/>';
        print_r(Hex::encode($fipsEngine->getFieldSymmetricKey('foo', 'bar')->getRawKey()));
        echo '<br/>';

        
        //index type column
        print_r($fipsEngine->getIndexTypeColumn('contacts', 'ssn', 'contact_ssn_last_four'));
        //result diatas sama dengan di encrypt.php di blind index contact_ssn_last_four
        echo '<br/>';
        print_r($fipsEngine->getIndexTypeColumn('tesu', '1235', 'quuy'));
        echo '<br/>';

        //encoded 
        print_r(Hex::encode($fipsEngine->getIndexTypeColumn('contacts', 'ssn', 'contact_ssn_last_four')));
        echo '<br/>';
        print_r(Hex::encode($fipsEngine->getIndexTypeColumn('tesu', '1235', 'quuy')));
        echo "<br/>";
        echo "====================";
        echo "<br/>";
        echo "<br/>";
        echo "<br/>";
        echo "<br/>";
        //encrypt single field (khusus string) EncryptedField
            //from low to high bit
                $eF = $this->encryptField($fipsEngine, false, false);
                $message = 'This is a test message: from jennifer';
                echo $message;
                echo "<br/>";
                echo "====================";
                echo "<br/>";
                $fCipher = $eF->encryptValue($message); 
                echo '<pre>';
                print_r($fCipher);
                echo " -> ".strlen($fCipher)." karakter";
                echo '</pre>';
                echo "====================";
                echo "<br/>";

                $eF2 = $this->encryptField($fipsEngine, true, true);
                $message2 = 'This is a test message: from jennifer2';
                echo $message2;
                echo "<br/>";
                echo "====================";
                echo "<br/>";
                $fCipher2 = $eF2->encryptValue($message2); 
                echo '<pre>';
                print_r($fCipher2);
                echo " -> ".strlen($fCipher2)." karakter";
                echo '</pre>';

        //decrypt single field
                echo "<br/>";
                echo "====================";
                echo "<br/>";
            echo $eF->decryptValue($fCipher);
                echo "<br/>";
                echo "====================";
                echo "<br/>";
            echo $eF2->decryptValue($fCipher2);

        //encrypt multiple field without Index (unable to search)
            echo '<br/>';
            $this->encryptRowWithoutIndex($fipsEngine);

        //encrypt multiple field with Index
            echo '<br/>';
            $this->encryptRowWithIndex($fipsEngine);
        
        //encrypt multiple row
            echo '<br/>';
            echo ">>>>>>>>>>>>>>>>>>>>>>>>>>>";
            echo "<br/>";
            $this->encryptMultiRowWithIndex($fipsEngine);

        exit;   
    }

    public function encryptField(CipherSweet $backend, $longer = false, $fast = false)
    {
        return (new EncryptedField($backend, 'contacts', 'ssn'))
            // Add a blind index for the "last 4 of SSN":
            ->addBlindIndex(
                new BlindIndex(
                // Name (used in key splitting):
                    'contact_ssn_last_four',
                    // List of Transforms:
                    [new LastFourDigits()],
                    // Output length (bytes)
                    $longer ? 64 : 16,
                    $fast
                )
            )
            ->addBlindIndex(
                new BlindIndex(
                // Name (used in key splitting):
                    'contact_ssn_last_4',
                    // List of Transforms:
                    [new LastFourDigits()],
                    // Output length (bytes)
                    $longer ? 64 : 16,
                    $fast
                )
            )
            // Add a blind index for the full SSN:
            ->addBlindIndex(
                new BlindIndex(
                    'contact_ssn',
                    [],
                    $longer ? 128 : 32,
                    $fast
                )
            );
    }

    public function encryptRowWithoutIndex(CipherSweet $backend)
    {
        echo '<br/>Encrypt - Decrypt without Index<br/>';
        $eF = (new EncryptedRow($backend, 'contacts'));
        $eF->addTextField('message');
        $eF->addTextField('id');

        $message = "This is from jennifer, different format";
        $row = [
            'message' => $message,
            'id' => 129
        ];
        
        $fCipher = $eF->encryptRow($row);
        echo '<pre>';
        print_r($fCipher);
        echo '</pre>';
        echo "<br/>";
        echo "====================";
        echo "<br/>";
        echo '<pre>';
        print_r($eF->decryptRow($fCipher));
        echo '</pre>';
    }

    public function encryptRowWithIndex(CipherSweet $backend)
    {
        $row = (new EncryptedRow($backend, 'contacts'))
            ->addTextField('customer_address')
            ->addTextField('customer_email')
            ->addBooleanField('status_amazon');

        $row->addBlindIndex(
            'customer_address',
            new BlindIndex(
            // Name (used in key splitting):
                'idx_customer-address',
                // List of Transforms:
                [new LastFourDigits()],
                // Output length (bytes)
                64,
                true
            )
        );
        $row->createCompoundIndex(
            'idx_cpd_customer-id_customer-address',
            ['customer_id', 'customer_address'],
            64,
            true
        );
        
        $data = [
            [
                'customer_id' => 29,
                'customer_address' => 'Jl, Sesetan Gg. Cemara no. 11',
                'customer_email' => 'rohaye.maimunah@gmail.com',
                'status' => 'active',
                'status_amazon' => true
            ],
            [
                'customer_id' => 30,
                'customer_address' => 'Jl, Belimbing no. 34',
                'customer_email' => 'bambang.purnomo@gmail.com',
                'status' => 'active',
                'status_amazon' => true
            ]
        ];

        $eF = $row->setFlatIndexes(true);

        $indexes = $eF->getAllBlindIndexes($data[0]);
        $indexes2 = $eF->getAllBlindIndexes($data[1]);
        echo '<pre>';
        print_r($indexes);
        print_r($indexes2);
        echo '</pre>';
        echo '<pre>';
        $blind_index = [];
        foreach($data as $d){
            print_r($fCipher[] = $eF->encryptRow($d));
            $blind_index['idx_customer-address'][] = $eF->getBlindIndex('idx_customer-address', $d);
        }
        echo '</pre>';
        print_r($eF->getBlindIndex('idx_customer-address', $data[0]));
        echo '<pre>';
        $i = 0;
        foreach($fCipher as $d){
            print_r($eF->decryptRow($d));
        }
        echo '</pre>';
        echo '<br/>';
        echo '=======================';
        echo '<br/>';
        /**
         * jadi konsep carinya memanfaatkan index, karena index juga akan tersimpan di db
         * coba liat $indexes dan $indexes, itu adalah kunci untuk nanti query di database. 
         * setelah ketemu, baru di decrypt
         */
        // var_dump($row->prepareForStorage($data[0]));
    }

    public function encryptMultiRowWithIndex(CipherSweet $backend)
    {
        $row = (new EncryptedMultiRows($backend, true))
                ->addTable('foo')
                ->addTable('bar');
        $row->addIntegerField('foo', 'column1')
            ->addTextField('foo', 'column2')
            ->addBooleanField('foo', 'column3');
        $row->addIntegerField('bar', 'column1');
        $row->addIntegerField('baz', 'column1');

        $row->addBlindIndex(
            'foo',
            'column2',
            (new BlindIndex('foo_column2_idx', [new Lowercase()], 32, true))
        );

        $data = [
            'foo' => [
                'id' => 123456,
                'column1' => 654321,
                'column2' => 'paragonie',
                'column3' => true,
                'extra' => 'test'
            ],
            'bar' => [
                'id' => 554353,
                'foo_id' => 123456,
                'column1' => 654321
            ],
            'baz' => [
                'id' => 3174521,
                'foo_id' => 123456,
                'column1' => 654322
            ]
        ];

        $row->setTypedIndexes(true);
        $encryptRows = $row->prepareForStorage($data);
        echo '<pre>';
        print_r($encryptRows);
        echo 'xxxxxxxxxxxxDECRYPTxxxxxxxxxxxxx<br/>';
        print_r($row->decryptManyRows($encryptRows[0]));
        echo '</pre>';

        exit;
        foreach($row->listTables() as $table){
            print_r($row->getTypedIndexes());
            print_r($row->getEncryptedRowObjectForTable($table)->getTypedIndexes());
        }
    }
}

$ciphersweettest = new CipherSweetTest();
$ciphersweettest->testBasicAPI();
$ciphersweettest->encrypt();
