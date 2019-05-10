<?php
/**
 * REST API: Tests for the WP_REST_Key_Pair class.
 *
 * @package JWTAuth
 * @subpackage REST_API
 * @since 0.1
 */

/**
 * Class Test_WP_REST_Key_Pair
 *
 * @since 0.1
 * @coversDefaultClass WP_REST_Key_Pair
 */
class Test_WP_REST_Key_Pair extends WP_UnitTestCase {

	/**
	 * REST Server.
	 *
	 * @var WP_REST_Server
	 */
	public $server;

	/**
	 * REST Key-pair.
	 *
	 * @var WP_REST_Key_Pair
	 */
	public $key_pair;

	/**
	 * User ID.
	 *
	 * @var int
	 */
	public $user_id;

	/**
	 * User object.
	 *
	 * @var WP_User
	 */
	public $user;

	/**
	 * Setup.
	 *
	 * @inheritdoc
	 */
	public function setUp() {
		parent::setUp();

		// @codingStandardsIgnoreStart
		$GLOBALS['wp_rest_server'] = new WP_REST_Server();
		// @codingStandardsIgnoreEnd

		$this->server = $GLOBALS['wp_rest_server'];
		do_action( 'rest_api_init' );

		$this->key_pair = new WP_REST_Key_Pair();
		$this->key_pair->init();

		$user_data = array(
			'role'       => 'administrator',
			'user_login' => 'testadmin',
			'user_pass'  => 'testpassword',
		);

		$this->user_id = $this->factory->user->create( $user_data );
		$this->user    = get_user_by( 'id', $this->user_id );
	}

	/**
	 * Teardown.
	 *
	 * @inheritdoc
	 */
	public function tearDown() {
		$this->server   = null;
		$this->key_pair = null;
		$this->user_id  = null;
		$this->user     = null;
		unset( $GLOBALS['wp_rest_server'] );
		parent::tearDown();
	}

	/**
	 * Test init().
	 *
	 * @covers ::init()
	 */
	public function test_init() {
		$this->assertEquals( 99, has_action( 'rest_api_init', array( $this->key_pair, 'register_routes' ) ) );
		$this->assertEquals( 10, has_action( 'show_user_profile', array( $this->key_pair, 'show_user_profile' ) ) );
		$this->assertEquals( 10, has_action( 'edit_user_profile', array( $this->key_pair, 'show_user_profile' ) ) );

		$this->assertEquals( 10, has_action( 'rest_authentication_require_token', array( $this->key_pair, 'require_token' ) ) );
		$this->assertEquals( 10, has_action( 'rest_authentication_user', array( $this->key_pair, 'authenticate' ) ) );
		$this->assertEquals( 10, has_action( 'rest_authentication_token_private_claims', array( $this->key_pair, 'payload' ) ) );
		$this->assertEquals( 10, has_action( 'rest_authentication_validate_token', array( $this->key_pair, 'validate_token' ) ) );
	}

	/**
	 * Test get_rest_uri().
	 *
	 * @covers ::get_rest_uri()
	 */
	public function test_get_rest_uri() {
		$this->assertEquals( '/index.php?rest_route=/wp/v2/key-pair', WP_REST_Key_Pair::get_rest_uri() );

		$this->set_permalink_structure( '/%postname%/' );
		$this->assertEquals( '/wp-json/wp/v2/key-pair', WP_REST_Key_Pair::get_rest_uri() );
		$this->set_permalink_structure( '' );
	}

	/**
	 * Test register_routes().
	 *
	 * @covers ::register_routes()
	 * @since 0.1
	 */
	public function test_register_routes() {
		$routes = $this->server->get_routes();
		$this->assertArrayHasKey( '/wp/v2/key-pair/(?P<user_id>[\d]+)', $routes );
		$this->assertArrayHasKey( '/wp/v2/key-pair/(?P<user_id>[\d]+)/revoke-all', $routes );
		$this->assertArrayHasKey( '/wp/v2/key-pair/(?P<user_id>[\d]+)/(?P<api_key>[\w-]+)/revoke', $routes );
	}

	/**
	 * Test get_item_schema().
	 *
	 * @covers ::get_item_schema()
	 * @since 0.1
	 */
	public function test_get_item_schema() {
		$schema = $this->key_pair->get_item_schema();
		$this->assertArrayHasKey( '$schema', $schema );
		$this->assertArrayHasKey( 'title', $schema );
		$this->assertArrayHasKey( 'type', $schema );
		$this->assertArrayHasKey( 'properties', $schema );
	}

	/**
	 * Test show_user_profile().
	 *
	 * @covers ::show_user_profile()
	 * @since 0.1
	 */
	public function test_show_user_profile() {
		do_action( 'wp_enqueue_scripts' );
		$this->get_show_user_profile();

		$this->assertTrue( wp_style_is( 'key-pair-css', 'enqueued' ) );
		$this->assertTrue( wp_script_is( 'key-pair-js', 'enqueued' ) );
	}

	/**
	 * Test after_password_reset().
	 *
	 * @covers ::after_password_reset()
	 * @since 0.1
	 */
	public function test_after_password_reset() {
		$user_data = array(
			'role'       => 'editor',
			'user_login' => 'testeditor',
			'user_pass'  => 'testpassword',
		);

		$user_id = $this->factory->user->create( $user_data );

		$this->assertEquals( array(), $this->key_pair->get_user_key_pairs( $user_id ) );

		$keypairs = array(
			array(
				'api_key'    => 12345,
				'api_secret' => 54321,
			),
		);
		update_user_meta( $user_id, WP_REST_Key_Pair::_USERMETA_KEY_, $keypairs );
		$this->assertEquals( $keypairs, $this->key_pair->get_user_key_pairs( $user_id ) );

		$this->key_pair->after_password_reset( get_user_by( 'ID', $user_id ) );
		$this->assertEquals( $keypairs, $this->key_pair->get_user_key_pairs( $user_id ) );

		reset_password( get_user_by( 'ID', $user_id ), 'testpassword1' );
		$this->assertEquals( array(), $this->key_pair->get_user_key_pairs( $user_id ) );
	}

	/**
	 * Test profile_update().
	 *
	 * @covers ::profile_update()
	 * @since 0.1
	 */
	public function test_profile_update() {
		global $wp_current_filter;

		$tmp = $wp_current_filter;

		$user_data = array(
			'role'       => 'editor',
			'user_login' => 'testeditor',
			'user_pass'  => 'testpassword',
		);

		$user_id = $this->factory->user->create( $user_data );

		$this->assertEquals( array(), $this->key_pair->get_user_key_pairs( $user_id ) );

		$keypairs = array(
			array(
				'api_key'    => 12345,
				'api_secret' => 54321,
			),
		);
		update_user_meta( $user_id, WP_REST_Key_Pair::_USERMETA_KEY_, $keypairs );
		$this->assertEquals( $keypairs, $this->key_pair->get_user_key_pairs( $user_id ) );

		$this->key_pair->profile_update( $user_id );
		$this->assertEquals( $keypairs, $this->key_pair->get_user_key_pairs( $user_id ) );

		$wp_current_filter = array(
			'profile_update',
		);
		$this->key_pair->profile_update( $user_id );
		$this->assertEquals( $keypairs, $this->key_pair->get_user_key_pairs( $user_id ) );

		$_POST['pass1'] = 'changed';
		$this->key_pair->profile_update( $user_id );
		$this->assertEquals( array(), $this->key_pair->get_user_key_pairs( $user_id ) );

		$wp_current_filter = $tmp;
	}

	/**
	 * Test require_token().
	 *
	 * @covers ::require_token()
	 * @since 0.1
	 */
	public function test_require_token() {
		$this->assertTrue( $this->key_pair->require_token( true, '/index.php?rest_route=/wp/v2/posts', 'POST' ) );
		$this->assertTrue( $this->key_pair->require_token( true, '/index.php?rest_route=/wp/v2/posts', 'DELETE' ) );

		$this->assertTrue( $this->key_pair->require_token( true, '/index.php?rest_route=/wp/v2/key-pair', 'GET' ) );
		$this->assertFalse( $this->key_pair->require_token( true, '/index.php?rest_route=/wp/v2/key-pair', 'POST' ) );
		$this->assertFalse( $this->key_pair->require_token( true, '/index.php?rest_route=/wp/v2/key-pair', 'DELETE' ) );

		$this->assertTrue( $this->key_pair->require_token( true, '/wp-json/wp/v2/key-pair', 'GET' ) );
		$this->assertFalse( $this->key_pair->require_token( true, '/wp-json/wp/v2/key-pair', 'POST' ) );
		$this->assertFalse( $this->key_pair->require_token( true, '/wp-json/wp/v2/key-pair', 'DELETE' ) );
	}

	/**
	 * Test authenticate().
	 *
	 * @covers ::authenticate()
	 * @since 0.1
	 */
	public function test_authenticate() {
		$keypairs = array(
			array(
				'api_key'    => '12345',
				'api_secret' => wp_hash( '54321' ),
			),
			array(
				'api_key'    => '678910',
				'api_secret' => wp_hash( '109876' ),
			),
		);

		$request = new WP_REST_Request( 'POST', 'wp/v2/key-pair' );
		$request->set_param( 'api_key', '12345' );

		$this->assertTrue( $this->key_pair->authenticate( true, $request ) );

		$this->assertFalse( $this->key_pair->authenticate( false, $request ) );

		$request->set_param( 'api_secret', '54321' );
		$response = $this->key_pair->authenticate( false, $request );
		$this->assertTrue( is_wp_error( $response ) );
		$this->assertEquals( $response->get_error_code(), 'rest_authentication_invalid_api_key_secret' );

		$this->key_pair->set_user_key_pairs( $this->user_id, $keypairs );
		unset( $keypairs[0] );
		$this->key_pair->set_user_key_pairs( $this->user_id, $keypairs );

		$response = $this->key_pair->authenticate( false, $request );
		$this->assertTrue( is_wp_error( $response ) );
		$this->assertEquals( $response->get_error_code(), 'rest_authentication_revoked_api_key' );

		$request->set_param( 'api_key', '678910' );
		$request->set_param( 'api_secret', '109876' );
		$response = $this->key_pair->authenticate( false, $request );
		$this->assertEquals( $response->data->ID, $this->user_id );
	}

	/**
	 * Test payload().
	 *
	 * @covers ::payload()
	 * @since 0.1
	 */
	public function test_payload() {
		$time     = time();
		$reserved = array(
			'iat'  => $time, // Token issued at.
			'exp'  => $time + WEEK_IN_SECONDS, // Token expiry.
			'data' => array(
				'user' => array(
					'type' => 'wp_user',
				),
			),
		);

		$user = json_decode(
			wp_json_encode(
				array(
					'data' => array(
						'api_key' => 12345,
					),
				)
			)
		);

		$payload = $this->key_pair->payload( $reserved, $user );
		$this->assertEquals( $payload['data']['user']['api_key'], 12345 );
	}

	/**
	 * Test validate_token().
	 *
	 * @covers ::validate_token()
	 * @since 0.1
	 */
	public function test_validate_token() {
		$keypairs = array(
			array(
				'name'       => 'Some Name',
				'api_key'    => 12345,
				'api_secret' => 54321,
				'created'    => time(),
				'last_used'  => null,
				'last_ip'    => null,
			),
		);

		$jwt = json_decode(
			wp_json_encode(
				array(
					'data' => array(
						'user' => array(
							'id'      => $this->user_id,
							'type'    => 'wp_user',
							'api_key' => 12345,
						),
					),
				)
			)
		);

		$this->assertFalse( $this->key_pair->validate_token( false ) );

		$this->key_pair->set_user_key_pairs( $this->user_id, $keypairs );
		$this->assertEquals( $jwt, $this->key_pair->validate_token( $jwt ) );

		$this->key_pair->set_user_key_pairs( $this->user_id, array() );
		$validate_token = $this->key_pair->validate_token( $jwt );
		$this->assertTrue( is_wp_error( $validate_token ) );
		$this->assertEquals( $validate_token->get_error_code(), 'rest_authentication_revoked_api_key' );
	}

	/**
	 * Test generate_key_pair().
	 *
	 * @covers ::generate_key_pair()
	 * @since 0.1
	 */
	public function test_generate_key_pair() {
		$user_data = array(
			'role'       => 'editor',
			'user_login' => 'testeditor',
			'user_pass'  => 'testpassword',
		);

		$user_id = $this->factory->user->create( $user_data );
		wp_set_current_user( $user_id, 'testeditor' );

		$request = new WP_REST_Request( 'POST', 'wp/v2/key-pair' );

		$key_pair = $this->key_pair->generate_key_pair( $request );
		$this->assertTrue( is_wp_error( $key_pair ) );
		$this->assertEquals( $key_pair->get_error_code(), 'rest_authentication_required_name_error' );

		$request->set_param( 'name', 'Custom Key-pair' );
		$key_pair = $this->key_pair->generate_key_pair( $request );
		$this->assertTrue( is_wp_error( $key_pair ) );
		$this->assertEquals( $key_pair->get_error_code(), 'rest_authentication_invalid_user_error' );

		$request->set_param( 'user_id', $this->user_id );
		$key_pair = $this->key_pair->generate_key_pair( $request );
		$this->assertTrue( is_wp_error( $key_pair ) );
		$this->assertEquals( $key_pair->get_error_code(), 'rest_authentication_edit_user_error' );

		// Set correct credentials.
		$request->set_param( 'user_id', $user_id );
		$key_pair = $this->key_pair->generate_key_pair( $request );
		$this->assertObjectHasAttribute( 'api_secret', $key_pair );
		$this->assertObjectHasAttribute( 'row', $key_pair );
		$this->assertEquals( 'Custom Key-pair', $key_pair->row->name );
	}

	/**
	 * Test delete_key_pair().
	 *
	 * @covers ::delete_key_pair()
	 * @since 0.1
	 */
	public function test_delete_key_pair() {
		$user_data = array(
			'role'       => 'editor',
			'user_login' => 'testeditor',
			'user_pass'  => 'testpassword',
		);

		$user_id = $this->factory->user->create( $user_data );

		$request = new WP_REST_Request( 'POST', 'wp/v2/key-pair' );
		$request->set_param( 'api_key', 1234567890 );
		$request->set_param( 'user_id', $user_id );

		$keypairs = array(
			array(
				'api_key'    => 12345,
				'api_secret' => 54321,
			),
			array(
				'api_key'    => 678910,
				'api_secret' => 109876,
			),
		);
		$this->key_pair->set_user_key_pairs( $user_id, $keypairs );

		$deleted = $this->key_pair->delete_key_pair( $request );
		$this->assertTrue( is_wp_error( $deleted ) );
		$this->assertEquals( $deleted->get_error_code(), 'rest_authentication_edit_user_error' );

		wp_set_current_user( $user_id, 'testeditor' );
		$this->assertFalse( $this->key_pair->delete_key_pair( $request ) );

		$request->set_param( 'api_key', 12345 );
		$this->assertTrue( $this->key_pair->delete_key_pair( $request ) );
		$this->assertEquals( array( $keypairs[1] ), $this->key_pair->get_user_key_pairs( $user_id ) );
	}

	/**
	 * Test delete_all_key_pairs().
	 *
	 * @covers ::delete_all_key_pairs()
	 * @since 0.1
	 */
	public function test_delete_all_key_pairs() {
		$user_data = array(
			'role'       => 'editor',
			'user_login' => 'testeditor',
			'user_pass'  => 'testpassword',
		);

		$user_id = $this->factory->user->create( $user_data );

		$request = new WP_REST_Request( 'POST', 'wp/v2/key-pair' );
		$request->set_param( 'user_id', $user_id );

		$keypairs = array(
			array(
				'api_key'    => 12345,
				'api_secret' => 54321,
			),
		);
		$deleted  = $this->key_pair->delete_all_key_pairs( $request );

		$this->assertTrue( is_wp_error( $deleted ) );
		$this->assertEquals( $deleted->get_error_code(), 'rest_authentication_edit_user_error' );

		wp_set_current_user( $user_id, 'testeditor' );
		$this->assertEquals( 0, $this->key_pair->delete_all_key_pairs( $request ) );

		$this->key_pair->set_user_key_pairs( $user_id, $keypairs );
		$this->assertEquals( 1, $this->key_pair->delete_all_key_pairs( $request ) );
	}

	/**
	 * Test get_user_key_pairs().
	 *
	 * @covers ::get_user_key_pairs()
	 * @since 0.1
	 */
	public function test_get_user_key_pairs() {
		update_user_meta( 1, WP_REST_Key_Pair::_USERMETA_KEY_, 'some-bad-value' );
		$this->assertEquals( array(), $this->key_pair->get_user_key_pairs( 1 ) );

		$keypairs = array(
			array(
				'api_key'    => 12345,
				'api_secret' => 54321,
			),
		);
		update_user_meta( 1, WP_REST_Key_Pair::_USERMETA_KEY_, $keypairs );
		$this->assertEquals( $keypairs, $this->key_pair->get_user_key_pairs( 1 ) );
	}

	/**
	 * Test set_user_key_pairs().
	 *
	 * @covers ::set_user_key_pairs()
	 * @since 0.1
	 */
	public function test_set_user_key_pairs() {
		$keypairs = array(
			array(
				'api_key'    => 12345,
				'api_secret' => 54321,
			),
		);
		$this->key_pair->set_user_key_pairs( 1, $keypairs );
		$this->assertEquals( $keypairs, $this->key_pair->get_user_key_pairs( 1 ) );
	}

	/**
	 * Test show_key_pair_section().
	 *
	 * @covers ::show_key_pair_section()
	 * @since 0.1
	 */
	public function test_show_key_pair_section() {
		$this->assertContains( 'key-pairs-section', $this->get_show_user_profile() );
	}

	/**
	 * Test template_new_key_pair().
	 *
	 * @covers ::template_new_key_pair()
	 * @since 0.1
	 */
	public function test_template_new_key_pair() {
		$this->assertContains( 'tmpl-new-key-pair', $this->get_show_user_profile() );
	}

	/**
	 * Test template_new_token_key_pair().
	 *
	 * @covers ::template_new_token_key_pair()
	 * @since 0.1
	 */
	public function test_template_new_token_key_pair() {
		$this->assertContains( 'tmpl-new-token-key-pair', $this->get_show_user_profile() );
	}

	/**
	 * Test template_key_pair_row().
	 *
	 * @covers ::template_key_pair_row()
	 * @since 0.1
	 */
	public function test_template_key_pair_row() {
		$this->assertContains( 'tmpl-key-pair-row', $this->get_show_user_profile() );
	}

	/**
	 * Get the show_user_profile output.
	 *
	 * @since 0.1
	 */
	public function get_show_user_profile() {
		ob_start();
		$this->key_pair->show_user_profile( $this->user );
		$profile = ob_get_contents();
		ob_end_clean();

		return $profile;
	}
}
