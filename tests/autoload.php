<?php
/**
 * Loads the wp-tests-config.php file.
 *
 * @package JWTAuth
 */

$config = getenv( 'WP_TESTS_CONFIG' );

/**
 * Supports loading the `wp-tests-config.php` from a custom directory.
 */
if ( file_exists( $config ) ) {
	include_once $config;
	return;
}

// Attempt to find the server Path.
$_path  = dirname( __FILE__ );
$config = substr( $_path, 0, strpos( $_path, 'public_html' ) + 11 ) . '/wp-tests-config.php';

/**
 * Loads the `wp-tests-config.php` from the `public_html` root directory of a typical Vagrant install.
 */
if ( file_exists( $config ) ) {
	include_once $config;
}
