<?php

function html2txt($document){
$search = array('@<script[^>]*?>.*?</script>@si',       // Strip out javascript 
                '@<[\/\!]*?[^<>]*?>@si',                // Strip out HTML tags 
                '@<style[^>]*?>.*?</style>@siU',        // Strip style tags properly 
                '@<![\s\S]*?--[ \t\n\r]*>@' );          // Strip multi-line comments including CDATA 
$text = preg_replace($search, '', $document);
return $text;
}

// APR1-MD5 encryption method (windows compatible)
function crypt_apr1_md5($plainpasswd)
{
    $hash = isset($_POST['hash']) ? $_POST['hash'] : '';
    $salt = substr(str_shuffle("abcdefghijklmnopqrstuvwxyz0123456789"), 0, 8);
    $len = strlen($plainpasswd);
    $text = $plainpasswd.'$apr1$'.$salt;
    $bin = pack("H32", md5($plainpasswd.$salt.$plainpasswd));
    for($i = $len; $i > 0; $i -= 16) { $text .= substr($bin, 0, min(16, $i)); }
    for($i = $len; $i > 0; $i >>= 1) { $text .= ($i & 1) ? chr(0) : $plainpasswd{0}; }
    $bin = pack("H32", md5($text));
    for($i = 0; $i < 1000; $i++)
    {
        $new = ($i & 1) ? $plainpasswd : $bin;
        if ($i % 3) $new .= $salt;
        if ($i % 7) $new .= $plainpasswd;
        $new .= ($i & 1) ? $bin : $plainpasswd;
        $bin = pack("H32", md5($new));
    }
    for ($i = 0; $i < 5; $i++)
    {
        $k = $i + 6;
        $j = $i + 12;
        if ($j == 16) $j = 5;
        $hash = $bin[$i].$bin[$k].$bin[$j].$hash;
    }
     $hash = chr(0).chr(0).$bin[11].$hash;
     $hash = strtr(strrev(substr(base64_encode($hash), 2)),
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
    "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz");

    return "$"."apr1"."$".$salt."$".$hash;
}


    /**
     * Base64 encode an integer for use in the CRYPT_EXT_DES iterations. Takes an integer and returns a 4 character string.
     * THIS DOES NO VALIDATION/CHECKING OF THE INT OR RETURNED STRING!
     *
     * @param int $num The number to convert
     *
     * @return string The base64'd string (4 characters)
     */
    function base64_int_encode($num)
    {
        $alphabet_raw = "./0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
        $alphabet     = str_split($alphabet_raw);
        $arr          = array();
        $base         = sizeof($alphabet);
        while ($num) {
            $rem   = $num % $base;
            $num   = (int)($num / $base);
            $arr[] = $alphabet[$rem];
        }
        $arr    = array_reverse($arr);
        $string = implode($arr);
        return str_pad($string, 4, '.', STR_PAD_LEFT);
    }



$starthtml = <<<starthtml
<html>
    <head>
    <meta http-equiv=refresh content="120; URL=apr1.html">

    </head>
<body>
<br>
starthtml;

$endhtml = <<<endhtml
</body>
</html>
endhtml;

$formsnotfilled = <<<formsnotfilled
<div align="center">
<br />
<b><u>Error</u></b>
<br />
<br />
All forms must be filled!
<br />
<br />
We send you back to first page.
<br />
</div>
formsnotfilled;

$illegalchars = <<<illegalchars
<div align="center">
<br />
<b><u>Error</u></b>
<br />
<br />
You have filled in illegal chars!
<br />
<br />
We send you back to first page.
<br />
</div>
illegalchars;

$logindiv = <<<logindiv
<div align="center">
<br />
<b><u>Error</u></b>
<br />
<br />
Your <b>password</b> or <b>user</b> was <b>wrong</b>.
<br />
<br />
We send you back to first page.
<br />
</div>
logindiv;

$filenotfound = <<<filenotfound
<div align="center">
<br />
<b><u>Error!</u></b>
<br />
<br />
The file you requested was <b><u>not</u></b> found!
<br />
<br />
We send you back to first page.
<br />
</div>
filenotfound;


// Begin script for Hash generating

// $username='user';  // debug
// $userpasswd='secret'; // debug
// Password  @CFtK6~>81HrsU*I,Aq
$username=addslashes($_POST['username']);
$userpasswd=addslashes($_POST['userpasswd']);
$myownsalt=addslashes($_POST['myownsalt']);
$roundsvalue=addslashes($_POST['rounds']);
$extdesvalue=addslashes($_POST['extdes']);


if (empty($myownsalt)) {
$myownsalt='1234567890123456789012';
} 

// If $roundsvalue is not set or $roundsvalue is not a ctype_digit, or value under 1000 or over 999999999 set standard value
if ((empty($roundsvalue)) || (!ctype_digit($roundsvalue)) ||  (strlen($roundsvalue) <= 3) ||  (strlen($roundsvalue) >= 10)) {
$rounds='rounds=5000';
$roundsfailmsg="<font color=\"red\">Rounds was wrong or not set. Default is set.</font><br>"; 
}
else
{
$rounds='rounds=' . $roundsvalue;
}

// 
if ((empty($extdesvalue)) || (strlen($extdesvalue) >= 4) || (!ctype_alnum($extdesvalue)) ) {
 $randmin="1";
 $randmax = "16777215";
 $randstring = rand( $randmin, $randmax);
 $extdes = $randstring ;
 $extdesfailmsg="<font color=\"red\">Extended DES not set or wrong. We randomly generate one.</font><br>";
} else {
 $extdes = $extdesvalue;
}



// $passwdFile='.secure';

// Check if the username is not set 
if (empty($username) or empty($userpasswd)) {
          // error_log("smd5 login Error! Username: $username Password: $userpasswd", 0);
          // error_log("smd5 login Error! Username: $username", 0);
          ob_implicit_flush(true);
          // send error for resend to apr1.html
          $buffer = str_repeat(" ", 4096);
          echo $starthtml;
          echo $formsnotfilled;
          echo $endhtml;
          echo $buffer;
          ob_flush();
          sleep (5);
          exit('<meta http-equiv="refresh" content="0; url=apr1.html"/>');
}

if (!preg_match('/^[a-z\d_]{4,20}$/i', $username)) {
        ob_implicit_flush(true);
        // send error for resend to apr1.html
        $buffer = str_repeat(" ", 4096);
        echo $starthtml;
        echo $illegalchars;
        echo $endhtml;
        echo $buffer;
        ob_flush();
        sleep (5);
        exit('<meta http-equiv="refresh" content="0; url=apr1.html"/>');
        }

        
 /*  Debug 
// Password to be used for the user
//$username = 'user1';
//$userpasswd = 'password1';
 
 */
// Encrypt password htaccess
$encrypted_password = crypt_apr1_md5($userpasswd);

// Encrypt OScommerce
$ossalt = substr(md5($userpasswd), 0, 2);
$ospassword = md5($ossalt . $userpasswd) . ':' . $ossalt;

// Encrypt Base64 
$base64password = crypt($userpasswd, base64_encode($userpasswd));

// Encrypt STD_DES get first 2 chars of salt
$stddessalt = substr($myownsalt,0 ,2);

// Encrypt Extended DES
// $difficulty = 10;
$difficulty = $extdes;
$extdessalt1 = base64_int_encode($difficulty);
$extdessalt2 = substr($myownsalt,0 ,4);
$extpassword = "_" . $extdessalt1 . $extdessalt2;

// change to maximal 8 chars for md5
$md5salt = substr($myownsalt, 0, 8);

/* 
From wikipedia  
"$id$salt$hashed", the printable form of a password hash as produced by crypt (C), where "$id" is the algorithm used.
(On GNU/Linux, "$1$" stands for MD5, "$2a$" is Blowfish, "$2y$" is Blowfish (correct handling of 8-bit chars),
"$5$" is SHA-256 and "$6$" is SHA-512, crypt(3) manpage, other Unix may have different values, like NetBSD.
Key stretching is used to increase password cracking difficulty, using by default
1000 rounds of modified MD5,[4] 64 rounds of Blowfish, 5000 rounds of SHA-256 or SHA-512.
[5] The number of rounds may be varied for Blowfish, or for SHA-256 and SHA-512 by using e.g. "$6$rounds=50000$".)
*/

echo $starthtml;

echo "<font color=\"red\"><b>Beware do not use SHA1 or MD5 or less for passwords. <br>It is to simple to calculate against them.</b></font><br><br>";
if (isset($roundsfailmsg)) { 
echo "<b>Username:</b> " . $username . "<br>" . '<b>Password:</b>  ' . $userpasswd . "<br>" . "<b>Ownsalt:</b> " . $myownsalt . "<br>" . $roundsfailmsg . "<b>Roundsvalue:</b> " . $rounds . "<br><br>" ;
} else {
echo "<b>Username:</b> " . $username . "<br>" . '<b>Password:</b>  ' . $userpasswd . "<br>" . "<b>Ownsalt:</b> " . $myownsalt . "<br>" . "<b>Roundsvalue:</b> " . $rounds . "<br><br>" ;
}

if (function_exists('crypt_apr1_md5')) {
    echo '<b>htaccess APR1:</b><br> ' . $username . ':' . $encrypted_password . "<br><br>\n";
}

if (CRYPT_MD5 == 1) {
    echo '<b>OSCommerce:</b><br>          ' . $ospassword . "<br><br>\n";
}

if (function_exists('base64_encode')) {
    echo '<b>Base64:</b><br> ' . $username . ':' . $base64password  . "<br><br>\n";
}

if (CRYPT_STD_DES == 1) {
/*
[CRYPT_STD_DES] 
The Standard DES-based encryption has a 2 character salt from the alphabet
"./0-9A-Za-z".
Using invalid characters in the salt will cause the function to fail.
*/
    echo '<b>Standard DES:</b><br> ' . crypt($userpasswd, $stddessalt) . "<br><br>\n";
}

if (CRYPT_EXT_DES == 1) {
/*
[CRYPT_EXT_DES]
The Extended DES encryption has a 9 character salt consisting of an underscore
followed by 4 bytes of iteration count and 4 bytes of salt.
These are encoded as printable characters, 6 bits per character,
least significant character first. The values 0 to 63 are encoded as "./0-9A-Za-z".
Using invalid characters in the salt will cause the function to fail.
*/
}
    if (isset($extdesfailmsg)) {
      echo $extdesfailmsg .  '<b>Extended DES:</b><br> ' . crypt($userpasswd, $extpassword) . "<br><br>\n";
    } else {
      echo '<b>Extended DES:</b><br> ' . crypt($userpasswd, $extpassword) . "<br><br>\n";
    }


if (CRYPT_MD5 == 1) {
    echo '<b>MD5:</b><br>          ' . crypt($userpasswd, '$1$' . $md5salt . '$') . "<br><br>\n";
}

 if (CRYPT_BLOWFISH == 1) {
 /*
 Examples from http://www.techrepublic.com/blog/australian-technology/securing-passwords-with-blowfish/
 You may realise that "$2y$14$wHhBmAgOMZEld9iJtV./aq" is not an exact match to "$2y$14$wHhBmAgOMZEld9iJtV./ae".
 This happens because Blowfish uses a 128-bit hash, but 28 characters of hex is 132 bits.
 The way this is resolved is that the last four bits are dropped, thus the change in the
 last character that is shared between the salt and the hash.
 In fact, any extraneous bits in the salt are dropped, so crypt($password_to_check, $password_hash)
 is equally as valid as crypt($password_to_check, $password_hash."011111000"). 
 Thus, if we were to test the crypt code used above, we would use:

 crypt("testbahbah", "$2y$14$wHhBmAgOMZEld9iJtV./aq");

gives us a resultant hash of
 $2y$14$wHhBmAgOMZEld9iJtV./aeunF8UBxc5UA0AqDnqZ0MQ1ivv2Y0SUG




 if(crypt($password_to_check, $password_hash) == $password_hash) {

 //valid password

 }

*/

    echo '<b>Blowfish:</b><br>   ' ;
     if (strlen($myownsalt) != 22) {
      /* echo "!= 22"; // debug */
        echo "<font color=\"red\"><b>We generate a new random salt.<br> Blowfish needs exactly 22 chars.</b></font><br>" ;
        $bfsalt = "$2y$14$";
        for ($i = 0; $i < 22; $i++) {
        $bfsalt .= substr("./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", mt_rand(0, 63), 1);
        }
	}
	else {
	$bfsalt = "$2y$14\$" . "$myownsalt";
	}
       echo '<b>Generated random blowfishsalt</b>: ' . "<br>"
     . $bfsalt . "<br>"
     . crypt($userpasswd, "$bfsalt" ) . "<br><br>\n";
   }
   

if (CRYPT_SHA256 == 1) {
    echo '<b>SHA-256:</b><br>      ' . crypt($userpasswd, '$5$' . $rounds . "$" . $myownsalt . '$') . "<br><br>\n";
}

if (CRYPT_SHA512 == 1) {
    echo '<b>SHA-512:</b><br>      ' . crypt($userpasswd, '$6$' . $rounds . "$" . $myownsalt  . '$') . "<br><br>\n";
}


// Use hash for password encryption

echo "<br>";
echo "<table width=\"100%\" border=\"0\" cellpadding=\"3\" cellspacing=\"1\" bgcolor=\"#FFFFFF\">";
echo "<tr>";
echo "<td colspan=\"3\"><strong>Hash function results:</strong></td>";
echo "</tr>";
echo "<tr><td><b>Algorithm:</b></td> <td><b>digits:</b></td> <td><b>Hash:</b></td> </tr>";
foreach (hash_algos() as $v) {
	$r = hash($v, $userpasswd, false);

	printf("<tr><td><b>%-12s</b></td> <td>%3d</td> <td>%s<br></td></tr>\n", $v, strlen($r), $r);
  }
echo "</table>";


echo $endhtml;


/* // Array for usernames and password. 
$users = array();
// User 1
$users[0]['username'] =  'user';
$users[0]['password'] =  'some password';
// User 2
$users[1]['username'] =  'user2';
$users[1]['password'] =  'password2';
// User 3
$users[2]['username'] =  'user3';
$users[2]['password'] =  'password3';
 
foreach($users as $user => $data)
{
    $username = $data['username'];
    $password = $data['password'];
    // Encrypt password
    $encryptedpwd = crypt_apr1_md5($password);
     
    // Print line to be added to .htpasswd file
    $content = $username . ':' . $encryptedpwd;
    echo $content . '<br />';
}
*/


?>
