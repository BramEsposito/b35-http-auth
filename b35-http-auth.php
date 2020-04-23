<?php

/**
 * Plugin Name: B35 Http Auth
 * Plugin URI: https://gist.github.com/BramEsposito/bbd5a6a03b2ce5dcda33f4a4827187b0
 * Description: Disable unauthenticated access to your site
 * Author: Bram Esposito
 * Version: 1.0
 * Author URI: https://bramesposito.com
 *
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
 * Add SetEnvIf Authorization .+ HTTP_AUTHORIZATION=$0 to your .htaccess
 */

add_action( 'wp_loaded', function() {

  // always allow cli clients
  if (php_sapi_name() == "cli") return;

  // Detect if we are on a test environment.
  // Implement your own method.
  // Or just remove the next line and do not deploy this file on production.
  if (b35_isProduction()) return;

  // FCGI wrapper fix
  if(in_array(php_sapi_name(), ['cgi-fcgi', 'fpm-fcgi'])) {

    // Ensure insert_with_markers() is declared
    require_once ABSPATH . 'wp-admin/includes/misc.php';

    // Get path to main .htaccess for WordPress
    $htaccess = trailingslashit($_SERVER['DOCUMENT_ROOT']).".htaccess";
    $lines = ["SetEnvIf Authorization .+ HTTP_AUTHORIZATION=$0"];
    insert_with_markers($htaccess, "b35-http-auth", $lines);
  }

  // I've put my credentials in an .env file and am retrieving them here.
  // Wordpress does not provide .env support so this would not work out of the box.
  // You can replace them with hardcoded credentials.
  $username = getenv('STAGING_USER');
  $password = getenv('STAGING_PWD');

  if (!isset($_SERVER['PHP_AUTH_USER'])) {
    header("X-auth:no credentials");
    b35_deny_access();
  } else {
    if ($_SERVER['PHP_AUTH_USER'] != $username || $_SERVER['PHP_AUTH_PW'] != $password) {
      header("X-auth:credentials incorrect");
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

if (!function_exists('b35_isProduction')) {
  function b35_isProduction() {
    if (defined('WP_ENV')) {
      return (WP_ENV == "production");
    }
    return $_SERVER['SERVER_ADDR'] != "127.0.0.1";
  }
}
