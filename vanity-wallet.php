#!/usr/bin/php
<?php
/* 
The MIT License (MIT)
Copyright (c) 2018 AroDev 
Morphed for vanity by ProgrammerDan

www.arionum.com

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE
OR OTHER DEALINGS IN THE SOFTWARE.
*/

error_reporting(0);


if (!extension_loaded("openssl") && !defined("OPENSSL_KEYTYPE_EC")) die("Openssl php extension missing\n");
if(floatval(phpversion())<7.2) die("The minimum php version required is 7.2\n");


   //all credits for this base58 functions should go to tuupola / https://github.com/tuupola/base58/
    function baseConvert(array $source, $source_base, $target_base)
    {
        $result = [];
        while ($count = count($source)) {
            $quotient = [];
            $remainder = 0;
            for ($i = 0; $i !== $count; $i++) {
                $accumulator = $source[$i] + $remainder * $source_base;
                $digit = (integer) ($accumulator / $target_base);
                $remainder = $accumulator % $target_base;
                if (count($quotient) || $digit) {
                    array_push($quotient, $digit);
                };
            }
            array_unshift($result, $remainder);
            $source = $quotient;
        }
        return $result;
    }
    function base58_encode($data)
    {
        if (is_integer($data)) {
            $data = [$data];
        } else {
            $data = str_split($data);
            $data = array_map(function ($character) {
                return ord($character);
            }, $data);
        }


        $converted = baseConvert($data, 256, 58);

        return implode("", array_map(function ($index) {
                $chars="123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
            return $chars[$index];
        }, $converted));
    }
     function base58_decode($data, $integer = false)
    {
        $data = str_split($data);
        $data = array_map(function ($character) {
                $chars="123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
            return strpos($chars, $character);
        }, $data);
        /* Return as integer when requested. */
        if ($integer) {
            $converted = baseConvert($data, 58, 10);
            return (integer) implode("", $converted);
        }
        $converted = baseConvert($data, 58, 256);
        return implode("", array_map(function ($ascii) {
            return chr($ascii);
        }, $converted));
    }

// valid base58 chars? note this is for case insensitive matching so any case of any letter
// can have a valid match
function check_findable($data) {
	return preg_match('/^[1-9a-z]+$/i', $data);
}


function pem2coin ($data) {
    $data=str_replace("-----BEGIN PUBLIC KEY-----","",$data);
    $data=str_replace("-----END PUBLIC KEY-----","",$data);
    $data=str_replace("-----BEGIN EC PRIVATE KEY-----","",$data);
    $data=str_replace("-----END EC PRIVATE KEY-----","",$data);
    $data=str_replace("\n","",$data);
    $data=base64_decode($data);
    return base58_encode($data);
    
}

function get_address($hash){
	      for($i=0;$i<9;$i++) $hash=hash('sha512',$hash, true);	
			return base58_encode($hash);
     }


function coin2pem ($data, $is_private_key=false) {

    
    
       $data=base58_decode($data);
       $data=base64_encode($data);

        $dat=str_split($data,64);
        $data=implode("\n",$dat);

    if($is_private_key) return "-----BEGIN EC PRIVATE KEY-----\n".$data."\n-----END EC PRIVATE KEY-----\n";
    return "-----BEGIN PUBLIC KEY-----\n".$data."\n-----END PUBLIC KEY-----\n";
}
function ec_sign($data, $key){

    $private_key=coin2pem($key,true);
   
   
    $pkey=openssl_pkey_get_private($private_key);
  
    $k=openssl_pkey_get_details($pkey);


    openssl_sign($data,$signature,$pkey,OPENSSL_ALGO_SHA256);
  
    
    
    return base58_encode($signature);
    
}


function ec_verify($data, $signature, $key){

    

    $public_key=coin2pem($key);
   
    $signature=base58_decode($signature);
    
    $pkey=openssl_pkey_get_public($public_key);
  
    $res=openssl_verify($data,$signature,$pkey,OPENSSL_ALGO_SHA256);
  
 
    if($res===1) return true;
    return false;
}


echo "###########################\n";
echo "# Vanity wallet generator #\n";
echo "#      version 0.1        #\n";
echo "###########################\n";
echo "\n";

$bfile = readline("Enter base name for the wallet file -- .aro will be auto-appended? ");
if (file_exists($bfile.".aro")) die("That file already exists!\n");
$sanity = trim(readline("What is the shortest case insensitive string you would like to find anywhere in the wallet address? "));
if ($sanity && !check_findable($sanity)) die("Numbers and letters only, please\n");
$vanity = trim(readline("If more particular, what case insensitive string would you like the wallet to start with? "));
if ($vanity && !check_findable($vanity)) die("Numbers and letters only, please\n");

echo "Ok, we will look for [".$sanity."] or [".$vanity."]\n";

$args = array(
	"curve_name" => "secp256k1",
	"private_key_type" => OPENSSL_KEYTYPE_EC,
);

$start=time();
$count=0;
$icount=0;
while(1) {
	$key1 = openssl_pkey_new($args);
	
	openssl_pkey_export($key1, $pvkey);
	
	$private_key= pem2coin($pvkey);

	$pub = openssl_pkey_get_details($key1);
	
	$public_key= pem2coin($pub['key']);

        $address=get_address($public_key);

	if (($vanity && stripos($address, $vanity) !== FALSE && stripos($address, $vanity) === 0) ||
		($sanity && stripos($address, $sanity) !== FALSE && stripos($address, $sanity) >= 0)) {
		echo "Found a match: ".$address."\n";
		$cont = readline("Would you like to use this? (y/N) ");
		if(substr(strtolower(trim($cont)),0,1)=="y"){
			$wallet="arionum:$private_key:$public_key";

			$q=readline("Would you like to encrypt this wallet? (y/N) ");
			$encrypt=false;
			if(substr(strtolower(trim($q)),0,1)=="y"){
				do {
					$pass=readline("Password:");
					if(strlen($pass)<8) {
						echo "The password must be at least 8 characters long\n";
						continue;
				}
				$pass2=readline("Confirm Password:");
				if($pass==$pass2) break;
				else echo "The passwords did not match!\n";
				} while(1);
				$encrypt=true;
			}
			if($encrypt===true){
				$password = substr(hash('sha256', $pass, true), 0, 32);
				$iv=random_bytes(16);
				$wallet = base64_encode($iv.base64_encode(openssl_encrypt($wallet, 'aes-256-cbc', $password, OPENSSL_RAW_DATA, $iv)));
			}

			$res=file_put_contents($bfile.".aro",$wallet);
			echo "Your Address is: ".$address."\n";
			echo "Your Public Key is: $public_key\n";
			echo "Your Private Key is: $private_key\n";
			if($res===false||$res<30) die("Could not write to ".$bfile.".aro wallet file! Please check the permissions on the current directory.\n");
			break;
		}
	}
	$count++;
	$icount++;
	if ($icount == 500) {
		$elapse = time() - $start;
		$icount = 0;
		echo "Checked ".$count." addresses so far in ".$elapse." seconds\n";
	}
}
