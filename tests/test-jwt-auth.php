<?php
/**
 * REST API: Tests for the jwt-auth.php file.
 *
 * @package JWTAuth
 * @subpackage REST_API
 * @since 0.1
 */

/**
 * Class Test_JWT_Auth
 *
 * @since 0.1
 */
class Test_JWT_Auth extends WP_UnitTestCase {

	/**
	 * Test jwt_auth_version_check().
	 *
	 * @since 0.1
	 */
	public function test_jwt_auth_version_check() {
		$this->assertEquals( 10, has_action( 'admin_init', 'jwt_auth_version_check' ) );
	}

	/**
	 * Test jwt_auth_loader().
	 *
	 * @since 0.1
	 */
	public function test_jwt_auth_loader() {
		do_action( 'plugins_loaded' );
		$this->assertEquals( 10, has_action( 'plugins_loaded', 'jwt_auth_loader' ) );
	}
}
