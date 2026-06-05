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

  // Credentials can be set from the WP admin screen (Settings > B35 Http Auth).
  // Those take precedence. If none are stored we fall back to the .env vars,
  // and if neither is configured we leave the gate open so a fresh install
  // can't lock the admin out of the settings screen.
  $db_username = (string) get_option('b35_http_auth_username', '');
  $db_pw_hash  = (string) get_option('b35_http_auth_password_hash', '');

  $given_user = $_SERVER['PHP_AUTH_USER'] ?? null;
  $given_pw   = $_SERVER['PHP_AUTH_PW'] ?? '';

  if ($db_username !== '' && $db_pw_hash !== '') {
    // Stored credentials: compare against the hashed password.
    $authed = $given_user !== null
      && hash_equals($db_username, $given_user)
      && wp_check_password($given_pw, $db_pw_hash);
  } else {
    // Fall back to the .env vars (the historic behaviour).
    $env_user = $_ENV['STAGING_USER'] ?? getenv('STAGING_USER');
    $env_pw   = $_ENV['STAGING_PWD'] ?? getenv('STAGING_PWD');

    // Nothing configured anywhere: don't lock anyone out.
    if (!is_string($env_user) || $env_user === '') return;

    $authed = $given_user !== null
      && hash_equals($env_user, $given_user)
      && hash_equals((string) $env_pw, $given_pw);
  }

  if ($given_user === null) {
    header("X-auth:no credentials");
    b35_deny_access();
  } elseif (!$authed) {
    header("X-auth:credentials incorrect");
    b35_deny_access();
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

/**
 * Admin screen (Settings > B35 Http Auth) to set the username/password used by
 * the gate above. The password is stored hashed, never in plain text.
 * Only registered off production, since the plugin only protects test sites.
 */
add_action('admin_menu', function() {
  if (b35_isProduction()) return;

  add_options_page(
    'B35 Http Auth',
    'B35 Http Auth',
    'manage_options',
    'b35-http-auth',
    'b35_http_auth_render_settings_page'
  );
});

add_action('admin_init', function() {
  register_setting('b35_http_auth', 'b35_http_auth_username', [
    'type'              => 'string',
    'sanitize_callback' => 'sanitize_text_field',
    'default'           => '',
  ]);

  register_setting('b35_http_auth', 'b35_http_auth_password_hash', [
    'type'              => 'string',
    'sanitize_callback' => 'b35_http_auth_sanitize_password',
    'default'           => '',
  ]);

  add_settings_section(
    'b35_http_auth_section',
    'Staging credentials',
    function() {
      echo '<p>Credentials for the HTTP Basic Auth prompt shown to anonymous '
         . 'visitors on this (non-production) site. Leave both blank to fall '
         . 'back to the <code>STAGING_USER</code> / <code>STAGING_PWD</code> '
         . 'environment variables.</p>';
    },
    'b35-http-auth'
  );

  add_settings_field(
    'b35_http_auth_username',
    'Username',
    function() {
      printf(
        '<input type="text" name="b35_http_auth_username" value="%s" class="regular-text" autocomplete="off" />',
        esc_attr(get_option('b35_http_auth_username', ''))
      );
    },
    'b35-http-auth',
    'b35_http_auth_section'
  );

  add_settings_field(
    'b35_http_auth_password_hash',
    'Password',
    function() {
      $is_set = get_option('b35_http_auth_password_hash', '') !== '';
      // The field is intentionally write-only: we never echo the stored hash.
      printf(
        '<input type="password" name="b35_http_auth_password_hash" value="" class="regular-text" autocomplete="new-password" placeholder="%s" />',
        $is_set ? esc_attr__('Leave blank to keep current password') : ''
      );
      echo '<p class="description">'
         . ($is_set
            ? 'A password is set. Enter a new one to change it, or leave blank to keep it.'
            : 'No password set yet.')
         . '</p>';
    },
    'b35-http-auth',
    'b35_http_auth_section'
  );
});

/**
 * Hash a submitted password, or keep the existing hash when the field is left
 * blank so saving the form doesn't wipe the stored password.
 */
function b35_http_auth_sanitize_password($input) {
  $input = (string) $input;
  if ($input === '') {
    return (string) get_option('b35_http_auth_password_hash', '');
  }
  // WordPress runs the sanitize callback twice when an option is created for
  // the first time (update_option() falls back to add_option(), which
  // sanitizes again). Without this guard the second pass would hash the
  // already-hashed value, so wp_check_password() could never match.
  // phpass hashes start with $P$/$H$, bcrypt with $2y$, and WP 6.8+ wraps
  // them as $wp$ — if we see any of those, it's already hashed.
  if (preg_match('/^\$(wp|2[aby]|P|H)\$/', $input)) {
    return $input;
  }
  return wp_hash_password($input);
}

function b35_http_auth_render_settings_page() {
  if (!current_user_can('manage_options')) return;
  ?>
  <div class="wrap">
    <h1>B35 Http Auth</h1>
    <form action="options.php" method="post">
      <?php
      settings_fields('b35_http_auth');
      do_settings_sections('b35-http-auth');
      submit_button();
      ?>
    </form>
  </div>
  <?php
}
