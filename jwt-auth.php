<?php
/**
 * JWT Auth
 *
 * @package      JWTAuth
 * @author       XWP
 * @license      GPL-2.0+
 *
 * @wordpress-plugin
 * Plugin Name:       JWT Auth
 * Plugin URI:        https://github.com/WP-API/jwt-auth
 * Description:       Feature plugin to bring JSON Web Token REST API authentication to Core
 * Version:           0.1
 * Author:            WP-API
 * Author URI:        https://github.com/WP-API/jwt-auth/graphs/contributors
 * Text Domain:       jwt-auth
 * License:           GPL-2.0+
 * License URI:       http://www.gnu.org/licenses/gpl-2.0.txt
 * GitHub Plugin URI: https://github.com/WP-API/jwt-auth
 * Requires PHP:      5.6.20
 * Requires WP:       5.2
 */

define( 'JWT_AUTH_PLUGIN_DIR', dirname( __FILE__ ) );
define( 'JWT_AUTH_PLUGIN_URL', plugin_dir_url( __FILE__ ) );
define( 'JWT_AUTH_VERSION', '0.1' );

/**
 * Requires running PHP 5.6.20 or above.
 *
 * @since 0.1
 * @codeCoverageIgnore
 */
function jwt_auth_version_check() {
	if ( version_compare( PHP_VERSION, '5.6.20', '<' ) ) {
		deactivate_plugins( plugin_basename( __FILE__ ) );
		wp_die( esc_html__( 'The JWT Auth plugin requires PHP Version 5.6.20 or above.', 'jwt-auth' ) );
	}
}
add_action( 'admin_init', 'jwt_auth_version_check' );

/**
 * Load the JWT Auth plugin.
 *
 * @since 0.1
 */
function jwt_auth_loader() {

	// JWT Classes.
	foreach ( glob( JWT_AUTH_PLUGIN_DIR . '/wp-includes/php-jwt/*.php' ) as $filename ) {
		require_once $filename;
	}

	// WP_REST_Token Class.
	require_once JWT_AUTH_PLUGIN_DIR . '/wp-includes/rest-api/auth/class-wp-rest-token.php';

	// WP_REST_Key_Pair Class.
	require_once JWT_AUTH_PLUGIN_DIR . '/wp-includes/rest-api/auth/class-wp-rest-key-pair.php';

	// WP_Key_Pair_List_Table Class.
	require_once JWT_AUTH_PLUGIN_DIR . '/wp-admin/includes/class-wp-key-pair-list-table.php';

	// Initialize JSON Web Tokens.
	$wp_rest_token = new WP_REST_Token();
	$wp_rest_token->init();

	// Initialize Key-pairs.
	$wp_rest_keypair = new WP_REST_Key_Pair();
	$wp_rest_keypair->init();
}
add_action( 'plugins_loaded', 'jwt_auth_loader' );
