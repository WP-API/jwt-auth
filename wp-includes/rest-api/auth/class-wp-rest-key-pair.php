<?php
/**
 * REST API: WP_REST_Key_Pair class.
 *
 * This class is responsible for adding/revoking a users API key:secret pairs.
 *
 * This class only allows REST authentication to the `{api_prefix}/wp/v2/token`
 * endpoint with an API key:secret. This allows a user to be identified via the
 * REST API without using their login credentials to generate a JSON Web Token.
 *
 * @package JWTAuth
 * @subpackage REST_API
 * @since 0.1
 */

/**
 * Core class used to manage REST API key-pairs which are used to generate JSON Web Tokens.
 *
 * @since 0.1
 */
class WP_REST_Key_Pair {

	/**
	 * The user meta key-pair key.
	 *
	 * @since 0.1
	 * @type string
	 */
	const _USERMETA_KEY_ = '_key_pairs';

	/**
	 * The namespace of the authentication route.
	 *
	 * @since 0.1
	 * @type string
	 */
	const _NAMESPACE_ = 'wp/v2';

	/**
	 * The base of the authentication route.
	 *
	 * @since 0.1
	 * @type string
	 */
	const _REST_BASE_ = 'key-pair';

	/**
	 * Initializes the class.
	 *
	 * @since 0.1
	 *
	 * @see add_action()
	 * @see add_filter()
	 */
	public function init() {
		add_action( 'rest_api_init', array( $this, 'register_routes' ), 99 );
		add_action( 'show_user_profile', array( $this, 'show_user_profile' ) );
		add_action( 'edit_user_profile', array( $this, 'show_user_profile' ) );
		add_action( 'after_password_reset', array( $this, 'after_password_reset' ) );
		add_action( 'profile_update', array( $this, 'profile_update' ) );

		add_filter( 'rest_authentication_require_token', array( $this, 'require_token' ), 10, 3 );
		add_filter( 'rest_authentication_user', array( $this, 'authenticate' ), 10, 2 );
		add_filter( 'rest_authentication_token_private_claims', array( $this, 'payload' ), 10, 2 );
		add_filter( 'rest_authentication_validate_token', array( $this, 'validate_token' ) );
	}

	/**
	 * Return the REST URI for the endpoint.
	 *
	 * @since 0.1
	 *
	 * @static
	 */
	public static function get_rest_uri() {
		$blog_id = get_current_blog_id();
		$prefix  = 'index.php?rest_route=';

		if ( is_multisite() && get_blog_option( $blog_id, 'permalink_structure' ) || get_option( 'permalink_structure' ) ) {
			$prefix = rest_get_url_prefix();
		}

		return sprintf( '/%s/%s/%s', $prefix, self::_NAMESPACE_, self::_REST_BASE_ );
	}

	/**
	 * Registers the routes for the authentication method.
	 *
	 * @since 0.1
	 *
	 * @see register_rest_route()
	 */
	public function register_routes() {
		$args = array(
			'methods'  => WP_REST_Server::CREATABLE,
			'callback' => array( $this, 'generate_key_pair' ),
			'args'     => array(
				'name'    => array(
					'description'       => esc_html__( 'The name of the key-pair.', 'jwt-auth' ),
					'type'              => 'string',
					'required'          => true,
					'sanitize_callback' => 'sanitize_text_field',
					'validate_callback' => 'rest_validate_request_arg',
				),
				'user_id' => array(
					'description'       => esc_html__( 'The ID of the user.', 'jwt-auth' ),
					'type'              => 'integer',
					'required'          => true,
					'sanitize_callback' => 'absint',
					'validate_callback' => 'rest_validate_request_arg',
				),
			),
			'schema'   => array( $this, 'get_item_schema' ),
		);
		register_rest_route( self::_NAMESPACE_, '/' . self::_REST_BASE_ . '/(?P<user_id>[\d]+)', $args );

		$args = array(
			'methods'  => WP_REST_Server::DELETABLE,
			'callback' => array( $this, 'delete_all_key_pairs' ),
			'args'     => array(
				'user_id' => array(
					'description'       => esc_html__( 'The ID of the user.', 'jwt-auth' ),
					'type'              => 'integer',
					'required'          => true,
					'sanitize_callback' => 'absint',
					'validate_callback' => 'rest_validate_request_arg',
				),
			),
		);
		register_rest_route( self::_NAMESPACE_, '/' . self::_REST_BASE_ . '/(?P<user_id>[\d]+)/revoke-all', $args );

		$args = array(
			'methods'  => WP_REST_Server::DELETABLE,
			'callback' => array( $this, 'delete_key_pair' ),
			'args'     => array(
				'user_id' => array(
					'description'       => esc_html__( 'The ID of the user.', 'jwt-auth' ),
					'type'              => 'integer',
					'required'          => true,
					'sanitize_callback' => 'absint',
					'validate_callback' => 'rest_validate_request_arg',
				),
				'api_key' => array(
					'description'       => esc_html__( 'The API key being revoked.', 'jwt-auth' ),
					'type'              => 'string',
					'required'          => true,
					'sanitize_callback' => 'sanitize_text_field',
					'validate_callback' => 'rest_validate_request_arg',
				),
			),
		);
		register_rest_route( self::_NAMESPACE_, '/' . self::_REST_BASE_ . '/(?P<user_id>[\d]+)/(?P<api_key>[\w-]+)/revoke', $args );
	}

	/**
	 * Retrieves the item schema, conforming to JSON Schema.
	 *
	 * @since 0.1
	 *
	 * @return array Item schema data.
	 */
	public function get_item_schema() {
		$schema = array(
			'$schema'    => 'http://json-schema.org/draft-04/schema#',
			'title'      => esc_html__( 'Key-pair', 'jwt-auth' ),
			'type'       => 'object',
			'properties' => array(
				'api_secret' => array(
					'description' => esc_html__( 'The raw API secret, which is not stored in the database.', 'jwt-auth' ),
					'type'        => 'string',
					'readonly'    => true,
				),
				'row'        => array(
					'description' => esc_html__( 'The stored key-pair data.', 'jwt-auth' ),
					'type'        => 'object',
					'readonly'    => true,
					'properties'  => array(
						'name'       => array(
							'description' => esc_html__( 'The name of the key-pair.', 'jwt-auth' ),
							'type'        => 'string',
							'readonly'    => true,
						),
						'api_key'    => array(
							'description' => esc_html__( 'The API key.', 'jwt-auth' ),
							'type'        => 'string',
							'readonly'    => true,
						),
						'api_secret' => array(
							'description' => esc_html__( 'The hashed API secret.', 'jwt-auth' ),
							'type'        => 'string',
							'readonly'    => true,
						),
						'created'    => array(
							'description' => esc_html__( 'The date the key-pair was created.', 'jwt-auth' ),
							'type'        => 'string',
							'readonly'    => true,
						),
						'last_used'  => array(
							'description' => esc_html__( 'The last time the key-pair was used.', 'jwt-auth' ),
							'type'        => 'string',
							'readonly'    => true,
						),
						'last_ip'    => array(
							'description' => esc_html__( 'The last IP address that used the key-pair.', 'jwt-auth' ),
							'type'        => 'string',
							'readonly'    => true,
						),
					),
				),
			),
		);

		/**
		 * Filters the REST endpoint schema.
		 *
		 * @param string $schema The endpoint schema.
		 */
		return apply_filters( 'rest_authentication_key_pair_schema', $schema );
	}

	/**
	 * Display the key-pair section in a users profile.
	 *
	 * @since 0.1
	 *
	 * @param WP_User $user WP_User object of the logged-in user.
	 */
	public function show_user_profile( WP_User $user ) {
		wp_enqueue_style( 'key-pair-css', JWT_AUTH_PLUGIN_URL . '/wp-admin/css/key-pair.css', array(), JWT_AUTH_VERSION );
		wp_enqueue_script( 'key-pair-js', JWT_AUTH_PLUGIN_URL . '/wp-admin/js/key-pair.js', array(), JWT_AUTH_VERSION, true );
		wp_localize_script(
			'key-pair-js',
			'keyPair',
			array(
				'nonce'   => wp_create_nonce( 'wp_rest' ),
				'root'    => self::get_rest_uri(),
				'token'   => WP_REST_Token::get_rest_uri(),
				'user_id' => $user->ID,
				'text'    => array(
					/* translators: %s: key-pair name */
					'confirm_one' => esc_html__( 'Revoke the %s key-pair? This action cannot be undone.', 'jwt-auth' ),
					'confirm_all' => esc_html__( 'Revoke all key-pairs? This action cannot be undone.', 'jwt-auth' ),
				),
			)
		);
		$this->show_key_pair_section( $user );
		$this->template_new_key_pair();
		$this->template_new_token_key_pair();
		$this->template_key_pair_row();
	}

	/**
	 * Fires after the user's password is reset.
	 *
	 * @param WP_User $user The user.
	 */
	public function after_password_reset( WP_User $user ) {
		if ( 'after_password_reset' !== current_filter() ) {
			return;
		}

		$keypairs = $this->get_user_key_pairs( $user->ID );
		if ( ! empty( $keypairs ) ) {
			$this->set_user_key_pairs( $user->ID, array() );
		}
	}

	/**
	 * Fires after the user's password is reset.
	 *
	 * When a user resets their password this method will deleted all of
	 * the application passwords associated with their account. In turn
	 * this will renders all JSON Web Tokens invalid for their account
	 *
	 * @param int $user_id The user ID.
	 */
	public function profile_update( $user_id ) {
		if ( 'profile_update' !== current_filter() ) {
			return;
		}

		if ( isset( $_POST['pass1'] ) && ! empty( $_POST['pass1'] ) ) { // phpcs:ignore
			$keypairs = $this->get_user_key_pairs( $user_id );
			if ( ! empty( $keypairs ) ) {
				$this->set_user_key_pairs( $user_id, array() );
			}
		}
	}

	/**
	 * Filters `rest_authentication_require_token` to exclude the key-pair endpoint,
	 *
	 * @param bool   $require_token Whether a token is required.
	 * @param string $request_uri The URI which was given by the server.
	 * @param string $request_method Which request method was used to access the server.
	 *
	 * @return bool
	 */
	public function require_token( $require_token, $request_uri, $request_method ) {

		// Don't require token authentication to manage key-pairs.
		if ( ( 'POST' === $request_method || 'DELETE' === $request_method ) && strpos( $request_uri, sprintf( '/%s/%s', self::_NAMESPACE_, self::_REST_BASE_ ) ) ) {
			$require_token = false;
		}

		return $require_token;
	}

	/**
	 * Authenticate the key-pair if API key and API secret is provided and return the user.
	 *
	 * If not authenticated, send back the original $user value to allow other authentication
	 * methods to attempt authentication. If the initial value of `$user` is false this method
	 * will return a `WP_User` object on success or a `WP_Error` object on failure. However,
	 * if the value is not `false` it will return that value, which could be any type of object.
	 *
	 * @filter rest_authentication_user
	 *
	 * @param mixed           $user    The user that's being authenticated.
	 * @param WP_REST_Request $request The REST request object.
	 *
	 * @return bool|object|mixed
	 */
	public function authenticate( $user, WP_REST_Request $request ) {

		if ( false !== $user ) {
			return $user;
		}

		$key    = $request->get_param( 'api_key' );
		$secret = $request->get_param( 'api_secret' );

		if ( ! $key || ! $secret ) {
			return $user;
		}

		// Retrieves a user if a valid key & secret is given.
		$get_user = get_users(
			array(
				'meta_key'   => $key, // phpcs:ignore
				'meta_value' => wp_hash( $secret ), // phpcs:ignore
			)
		);

		$get_user = is_array( $get_user ) && ! empty( $get_user ) ? array_shift( $get_user ) : false;

		if ( false === $get_user ) {
			return new WP_Error(
				'rest_authentication_invalid_api_key_secret',
				__( 'The API key-pair is invalid.', 'jwt-auth' ),
				array(
					'status' => 403,
				)
			);
		}

		$found    = false;
		$keypairs = $this->get_user_key_pairs( $get_user->ID );
		foreach ( $keypairs as $_key => $item ) {
			if ( isset( $item['api_key'] ) && $item['api_key'] === $key ) {
				$keypairs[ $_key ]['last_used'] = time();

				$ip = isset( $_SERVER['REMOTE_ADDR'] ) ? filter_var( wp_unslash( $_SERVER['REMOTE_ADDR'] ), FILTER_VALIDATE_IP ) : null;
				if ( $ip ) {
					$keypairs[ $_key ]['last_ip'] = $ip;
				}
				$this->set_user_key_pairs( $get_user->ID, $keypairs );
				$found = true;
				break;
			}
		}

		if ( false === $found ) {
			return new WP_Error(
				'rest_authentication_revoked_api_key',
				__( 'Token is invalid the API key has been revoked.', 'jwt-auth' ),
				array(
					'status' => 403,
				)
			);
		}

		// Add the api_key to use when encoding the JWT.
		$get_user->data->api_key = $key;

		return $get_user;
	}

	/**
	 * Filters the JWT Payload.
	 *
	 * Due to the fact that `$user` could have been filtered the object type is technically
	 * unknown. However, likely a `WP_User` object if auth has not been filtered. In any
	 * case, the object must have the `$user->data->api_key` property in order to connect
	 * the API key to the JWT payload and allow for token invalidation.
	 *
	 * @filter rest_authentication_token_private_claims
	 *
	 * @param array          $payload The payload used to generate the token.
	 * @param WP_User|Object $user The authenticated user object.
	 *
	 * @return array
	 */
	public function payload( $payload, $user ) {

		// Set the api_key. which we use later to validate a key-pair has not already been revoked.
		if ( isset( $user->data->api_key ) && isset( $payload['data']['user'] ) ) {
			$payload['data']['user']['api_key'] = $user->data->api_key;
		}

		return $payload;
	}

	/**
	 * Authenticate the key-pair if API key and API secret is provided and return the user.
	 *
	 * If not authenticated, send back the original $user value to allow other authentication
	 * methods to attempt authentication.
	 *
	 * @filter rest_authentication_validate_token
	 *
	 * @param object $jwt The JSON Web Token.
	 *
	 * @return object|WP_Error
	 */
	public function validate_token( $jwt ) {

		if ( ! isset( $jwt->data->user->api_key ) || ! isset( $jwt->data->user->id ) ) {
			return $jwt;
		}

		$found    = false;
		$keypairs = $this->get_user_key_pairs( $jwt->data->user->id );
		foreach ( $keypairs as $key => $item ) {
			if ( isset( $item['api_key'] ) && $item['api_key'] === $jwt->data->user->api_key ) {
				$found = true;
				break;
			}
		}

		if ( false === $found ) {
			return new WP_Error(
				'rest_authentication_revoked_api_key',
				__( 'Token is invalid the API key has been revoked.', 'jwt-auth' ),
				array(
					'status' => 403,
				)
			);
		}

		return $jwt;
	}

	/**
	 * Generate new API key-pair for user.
	 *
	 * A user must be logged in and have permission to create a key-pair.
	 * This means a request must be made in the wp-admin using a nonce and
	 * ajax, or through some other means of authentication like basic-auth.
	 *
	 * @param WP_REST_Request $request The requests.
	 *
	 * @return object|\WP_Error The key-pair or error.
	 */
	public function generate_key_pair( WP_REST_Request $request ) {
		$name    = $request->get_param( 'name' );
		$user_id = $request->get_param( 'user_id' );
		$user    = get_user_by( 'id', $user_id );

		if ( empty( $name ) ) {
			return new WP_Error(
				'rest_authentication_required_name_error',
				__( 'The key-pair name is required.', 'jwt-auth' ),
				array(
					'status' => 403,
				)
			);
		}

		if ( false === $user || ! ( $user instanceof WP_User ) ) {
			return new WP_Error(
				'rest_authentication_invalid_user_error',
				__( 'The user does not exist.', 'jwt-auth' ),
				array(
					'status' => 403,
				)
			);
		}

		if ( ! current_user_can( 'edit_user', $user_id ) ) {
			return new WP_Error(
				'rest_authentication_edit_user_error',
				__( 'You do not have permission to edit this user.', 'jwt-auth' ),
				array(
					'status' => 403,
				)
			);
		}

		$api_key       = $user->ID . wp_generate_password( 24, false );
		$api_secret    = wp_generate_password( 32 );
		$hashed_secret = wp_hash( $api_secret );

		$new_item = array(
			'name'       => $name,
			'api_key'    => $api_key,
			'api_secret' => $hashed_secret,
			'created'    => time(),
			'last_used'  => null,
			'last_ip'    => null,
		);

		$keypairs   = $this->get_user_key_pairs( $user_id );
		$keypairs[] = $new_item;
		$this->set_user_key_pairs( $user_id, $keypairs );

		$new_item['created']   = date( 'F j, Y g:i a', $new_item['created'] );
		$new_item['last_used'] = '—';
		$new_item['last_ip']   = '—';

		return json_decode(
			wp_json_encode(
				array(
					'api_secret' => $api_secret,
					'row'        => $new_item,
				)
			)
		);
	}

	/**
	 * Delete API key-pair for user.
	 *
	 * @param WP_REST_Request $request The requests.
	 *
	 * @return bool|WP_Error Whether the key-pair was deleted or error.
	 */
	public function delete_key_pair( WP_REST_Request $request ) {
		$api_key = $request->get_param( 'api_key' );
		$user_id = $request->get_param( 'user_id' );

		if ( ! current_user_can( 'edit_user', $user_id ) ) {
			return new WP_Error(
				'rest_authentication_edit_user_error',
				__( 'You do not have permission to edit this user.', 'jwt-auth' ),
				array(
					'status' => 403,
				)
			);
		}

		$keypairs = $this->get_user_key_pairs( $user_id );
		foreach ( $keypairs as $key => $item ) {
			if ( isset( $item['api_key'] ) && $item['api_key'] === $api_key ) {
				unset( $keypairs[ $key ] );
				$this->set_user_key_pairs( $user_id, $keypairs );
				return true;
			}
		}

		return false;
	}

	/**
	 * Delete all API key-pairs for a user.
	 *
	 * @param WP_REST_Request $request The requests.
	 *
	 * @return bool|WP_Error Number of key-pairs deleted or error.
	 */
	public function delete_all_key_pairs( WP_REST_Request $request ) {
		$user_id = $request->get_param( 'user_id' );

		if ( ! current_user_can( 'edit_user', $user_id ) ) {
			return new WP_Error(
				'rest_authentication_edit_user_error',
				__( 'You do not have permission to edit this user.', 'jwt-auth' ),
				array(
					'status' => 403,
				)
			);
		}

		$keypairs = $this->get_user_key_pairs( $user_id );
		if ( ! empty( $keypairs ) ) {
			$this->set_user_key_pairs( $user_id, array() );
			return count( $keypairs );
		}

		return 0;
	}

	/**
	 * Get a users key-pairs.
	 *
	 * @since 0.1
	 *
	 * @param int $user_id User ID.
	 * @return array
	 */
	public function get_user_key_pairs( $user_id ) {
		$keypairs = get_user_meta( $user_id, self::_USERMETA_KEY_, true );

		if ( ! is_array( $keypairs ) ) {
			return array();
		}

		return $keypairs;
	}

	/**
	 * Set a users keypairs.
	 *
	 * @since 0.1
	 *
	 * @param int   $user_id User ID.
	 * @param array $keypairs Keypairs.
	 *
	 * @return bool
	 */
	public function set_user_key_pairs( $user_id, $keypairs ) {
		if ( is_array( $keypairs ) && ! empty( $keypairs ) ) {
			foreach ( $keypairs as $keypair ) {
				if ( isset( $keypair['api_key'] ) && isset( $keypair['api_secret'] ) ) {
					add_user_meta( $user_id, $keypair['api_key'], $keypair['api_secret'], true );
				}
			}
		}

		return update_user_meta( $user_id, self::_USERMETA_KEY_, array_values( $keypairs ) );
	}

	/**
	 * The key-pair section.
	 *
	 * @since 0.1
	 *
	 * @param WP_User $user WP_User object of the logged-in user.
	 */
	public function show_key_pair_section( WP_User $user ) {
		?>
		<div class="key-pairs hide-if-no-js" id="key-pairs-section">
			<h2 id="key-pairs"><?php esc_html_e( 'API Key-pairs', 'jwt-auth' ); ?></h2>
			<p><?php esc_html_e( 'API key-pairs allow for generating JSON Web Tokens which are used for authentication via non-interactive systems, such as XMLRPC or the REST API, without providing your actual password. Key-pairs can be easily revoked, which also revokes the JSON Web Token. Both key-pairs and JSON Web Tokens cannot be used for traditional logins to your website.', 'jwt-auth' ); ?></p>
			<table class="form-table create-key-pair">
				<tbody>
					<tr>
						<th scope="row">
							<label for="new_key_pair_name"><?php esc_attr_e( 'New key-pair', 'jwt-auth' ); ?></label>
						</th>
						<td>
							<input type="text" size="30" name="new_key_pair_name" id="new_key_pair_name" placeholder="<?php esc_attr_e( 'Name', 'jwt-auth' ); ?>" class="input regular-text code" autocomplete="new-password" />
							<?php submit_button( esc_html__( 'Add New', 'jwt-auth' ), 'secondary', 'do_new_keypair', false ); ?>
						</td>
					</tr>
				</tbody>
			</table>
			<div class="key-pairs-list-table-wrapper">
				<?php
				$key_pair_list_table        = new WP_Key_Pair_List_Table( array( 'screen' => 'profile' ) );
				$key_pair_list_table->items = array_reverse( $this->get_user_key_pairs( $user->ID ) );
				$key_pair_list_table->prepare_items();
				$key_pair_list_table->display();
				?>
			</div>
		</div>
		<?php
	}

	/**
	 * The new key-pair template.
	 *
	 * @since 0.1
	 */
	public function template_new_key_pair() {
		?>
		<script type="text/html" id="tmpl-new-key-pair">
			<div class="new-key-pair notification-dialog-wrap">
				<div class="key-pair-dialog-background notification-dialog-background">
					<div class="key-pair-dialog notification-dialog">
						<div class="new-key-pair-content">
							<h3>{{ data.name }}</h3>
							<?php
							printf(
								/* translators: %s: key-pair api_secret */
								esc_html_x( 'Your new API secret password is: %s', 'API key-pair', 'jwt-auth' ),
								'<input type="text" value="{{ data.api_secret }}" class="input-select" />'
							);
							?>
						</div>
						<p><?php esc_attr_e( 'Be sure to save this password in a safe location, you will not be able to retrieve it ever again. Your API secret password is stored in the database like your login password and cannot be recovered. Once you click dismiss it is gone forever.', 'jwt-auth' ); ?></p>
						<p><?php esc_attr_e( 'You will need both the API key/secret to generate a JSON Web Token. You can download the key-pair.json file that contains both the API key/secret by clicking the button below.', 'jwt-auth' ); ?></p>
						<button class="button button-secondary key-pair-download" data-key="{{ data.api_key }}" data-secret="{{ data.api_secret }}"><?php esc_attr_e( 'Download', 'jwt-auth' ); ?></button>
						<button class="button button-primary key-pair-modal-dismiss"><?php esc_attr_e( 'Dismiss', 'jwt-auth' ); ?></button>
					</div>
				</div>
			</div>
		</script>
		<?php
	}

	/**
	 * The new token key-pair template.
	 *
	 * @since 0.1
	 */
	public function template_new_token_key_pair() {
		?>
		<script type="text/html" id="tmpl-new-token-key-pair">
			<div class="new-key-pair notification-dialog-wrap" data-api_key="{{ data.api_key }}"  data-name="{{ data.name }}">
				<div class="key-pair-dialog-background notification-dialog-background">
					<div class="key-pair-dialog notification-dialog">
						<h3><?php esc_attr_e( 'JSON Web Token', 'jwt-auth' ); ?></h3>
						<# if ( data.message ) { #>
						<div class="notice notice-error"><p>{{{ data.message }}}</p></div>
						<# } #>
						<# if ( ! data.access_token || ! data.refresh_token ) { #>
						<p>
							<?php
							printf(
								/* translators: %s: key-pair api_secret */
								esc_html_x( 'To generate a new JSON Web Token please enter your API Secret password for the %s key-pair below.', 'API key-pair', 'jwt-auth' ),
								'<strong>{{ data.name }}</strong>'
							);
							?>
						</p>
						<p>
							<?php
							printf(
								/* translators: %s: key-pair api_secret */
								esc_html_x( 'The API Secret must be a key-pair match for the API Key: %s.', 'API key-pair', 'jwt-auth' ),
								'<strong>{{ data.api_key }}</strong>'
							);
							?>
						</p>
						<input type="text" size="30" name="new_token_api_secret" placeholder="<?php esc_attr_e( 'API Secret', 'jwt-auth' ); ?>" class="input" autocomplete="new-password" />
						<button class="button button-secondary key-pair-token"><?php esc_attr_e( 'New Token', 'jwt-auth' ); ?></button>
						<# } else { #>
						<div class="new-key-pair-token">
							<?php
							printf(
								/* translators: %s: JSON Web Token */
								esc_html_x( 'Your new access token is: %s', 'Access Token', 'jwt-auth' ),
								'<input type="text" value="{{ data.access_token }}" class="input-select" />'
							);
							?>
							<?php
							printf(
								/* translators: %s: JSON Web Token */
								esc_html_x( 'Your new refresh token is: %s', 'Refresh Token', 'jwt-auth' ),
								'<input type="text" value="{{ data.refresh_token }}" class="input-select" />'
							);
							?>
							<p><?php esc_attr_e( 'Be sure to save these JSON Web Tokens in a safe location, you will not be able to retrieve them ever again. Once you click dismiss they\'re gone forever.', 'jwt-auth' ); ?></p>
						</div>
						<button class="button button-secondary key-pair-token-download"><?php esc_attr_e( 'Download', 'jwt-auth' ); ?></button>
						<# } #>
						<button class="button button-primary key-pair-modal-dismiss"><?php esc_attr_e( 'Dismiss', 'jwt-auth' ); ?></button>
					</div>
				</div>
			</div>
		</script>
		<?php
	}

	/**
	 * The key-pair row template.
	 *
	 * @since 0.1
	 */
	public function template_key_pair_row() {
		?>
		<script type="text/html" id="tmpl-key-pair-row">
			<tr data-api_key="{{ data.api_key }}" data-name="{{ data.name }}">
				<td class="name column-name has-row-actions column-primary" data-colname="<?php esc_attr_e( 'Name', 'jwt-auth' ); ?>">
					{{ data.name }}
				</td>
				<td class="name column-name column-api_key" data-colname="<?php esc_attr_e( 'API Key', 'jwt-auth' ); ?>">
					{{ data.api_key }}
				</td>
				<td class="created column-created" data-colname="<?php esc_attr_e( 'Created', 'jwt-auth' ); ?>">
					{{ data.created }}
				</td>
				<td class="last_used column-last_used" data-colname="<?php esc_attr_e( 'Last Used', 'jwt-auth' ); ?>">
					{{ data.last_used }}
				</td>
				<td class="last_ip column-last_ip" data-colname="<?php esc_attr_e( 'Last IP', 'jwt-auth' ); ?>">
					{{ data.last_ip }}
				</td>
				<td class="token column-token" data-colname="<?php esc_attr_e( 'Token', 'jwt-auth' ); ?>">
					<input type="submit" name="token-key-pair-{{ data.api_key }}" class="button" id="token-key-pair-{{ data.api_key }}" value="<?php esc_attr_e( 'New Token', 'jwt-auth' ); ?>">
				</td>
				<td class="revoke column-revoke" data-colname="<?php esc_attr_e( 'Revoke', 'jwt-auth' ); ?>">
					<input type="submit" name="revoke-key-pair" class="button delete" id="revoke-key-pair-{{ data.api_key }}" value="<?php esc_attr_e( 'Revoke', 'jwt-auth' ); ?>">
				</td>
			</tr>
		</script>
		<?php
	}
}
