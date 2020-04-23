<?php
/**
 * Description
 * ===========
 * Disable unauthenticated access to your site. This "Must-Use"-plugin presents
 * you with a login window when accessing the dynamic parts of the site. Static
 * files are not protected with this script!
 *
 * Installation
 * ============
 * Put this file in Wordpress's wp-content/mu-plugins directory.
 *
 * Known Issues
 * ============
 * Http Auth does not work when PHP is installed as a CGI wrapper. See
 * [the PHP http.auth documentation](http://uk.php.net/manual/en/features.http-auth.php)
 * for more information and potential workarounds.
 */

add_action( 'init', function() {

  // Detect if we are on a test environment.
  // Implement your own method.
  // Or just remove the next line and do not deploy this file on production.
  if (b35_isProduction()) return;

  // I've put my credentials in an .env file and am retrieving them here.
  // Wordpress does not provide .env support so this would not work out of the box.
  // You can replace them with hardcoded credentials.
  $username = getenv('STAGING_USER');
  $password = getenv('STAGING_PWD');

  if (!isset($_SERVER['PHP_AUTH_USER'])) {
    b35_deny_access();
  } else {
    if ($_SERVER['PHP_AUTH_USER'] != $username || $_SERVER['PHP_AUTH_PW'] != $password) {
      b35_deny_access();
    }
  }
} );

function b35_deny_access() {
  header('WWW-Authenticate: Basic realm="Staging"');
  header('HTTP/1.0 401 Unauthorized');
  echo 'You need to be logged in to see this page.';
  exit;
}
