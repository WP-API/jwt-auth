<?php
/**
 * REST API: WP_REST_Token class
 *
 * @package JWTAuth
 * @subpackage REST_API
 * @since 0.1
 */

use Firebase\JWT\JWT;

/**
 * Core class used to manage REST API authentication with JSON Web Tokens.
 *
 * @since 0.1
 */
class WP_REST_Token {

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
	const _REST_BASE_ = 'token';

	/**
	 * The secret key of the authentication route.
	 *
	 * @since 0.1
	 * @var string
	 */
	protected $secret_key;

	/**
	 * Constructor.
	 *
	 * @since 0.1
	 * @codeCoverageIgnore
	 */
	public function __construct() {

		// Use SECURE_AUTH_KEY defined in wp-config.php as the secret key.
		if ( ! defined( 'SECURE_AUTH_KEY' ) ) {
			return;
		}

		$this->secret_key = SECURE_AUTH_KEY;
	}

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
		add_filter( 'rest_authentication_errors', array( $this, 'authenticate' ) );
	}

	/**
	 * Return the REST URI for the endpoint.
	 *
	 * @since 0.1
	 *
	 * @static
	 */
	public static function get_rest_uri() {
		return sprintf( '/%s/%s/%s', rest_get_url_prefix(), self::_NAMESPACE_, self::_REST_BASE_ );
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
			'callback' => array( $this, 'generate_token' ),
			'args'     => array(
				'username'   => array(
					'description'       => __( 'The username of the user; requires also setting the password argument.', 'jwt-auth' ),
					'type'              => 'string',
					'sanitize_callback' => 'sanitize_user',
					'validate_callback' => 'rest_validate_request_arg',
				),
				'password'   => array(
					'description'       => __( 'The password of the user; requires also setting the username argument.', 'jwt-auth' ),
					'type'              => 'string',
					'sanitize_callback' => 'sanitize_text_field',
					'validate_callback' => 'rest_validate_request_arg',
				),
				'api_key'    => array(
					'description'       => __( 'The API key of the user; requires also setting the api_secret.', 'jwt-auth' ),
					'type'              => 'string',
					'sanitize_callback' => 'sanitize_text_field',
					'validate_callback' => 'rest_validate_request_arg',
				),
				'api_secret' => array(
					'description'       => __( 'The API secret of the user; requires also setting the api_key.', 'jwt-auth' ),
					'type'              => 'string',
					'sanitize_callback' => 'sanitize_text_field',
					'validate_callback' => 'rest_validate_request_arg',
				),
			),
			'schema'   => array( $this, 'get_item_schema' ),
		);
		register_rest_route( self::_NAMESPACE_, '/' . self::_REST_BASE_, $args );
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
			'title'      => __( 'JSON Web Token', 'jwt-auth' ),
			'type'       => 'object',
			'properties' => array(
				'access_token' => array(
					'description' => esc_html__( 'JSON Web Token.', 'jwt-auth' ),
					'type'        => 'string',
					'readonly'    => true,
				),
				'data'         => array(
					'description' => esc_html__( 'JSON Web Token private claim data.', 'jwt-auth' ),
					'type'        => 'object',
					'readonly'    => true,
					'properties'  => array(
						'user' => array(
							'description' => esc_html__( 'User object.', 'jwt-auth' ),
							'type'        => 'object',
							'readonly'    => true,
							'properties'  => array(
								'id'         => array(
									'description' => esc_html__( 'The ID of the user.', 'jwt-auth' ),
									'type'        => 'integer',
									'readonly'    => true,
								),
								'type'       => array(
									'description' => esc_html__( 'The type of user.', 'jwt-auth' ),
									'type'        => 'string',
									'readonly'    => true,
								),
								'user_login' => array(
									'description' => esc_html__( 'The username of the user.', 'jwt-auth' ),
									'type'        => 'string',
									'readonly'    => true,
								),
								'user_email' => array(
									'description' => esc_html__( 'The email address of the user.', 'jwt-auth' ),
									'type'        => 'string',
									'readonly'    => true,
								),
								'api_key'    => array(
									'description' => esc_html__( 'The API key of the user.', 'jwt-auth' ),
									'type'        => 'string',
									'readonly'    => true,
								),
							),
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
		return apply_filters( 'rest_authentication_token_schema', $schema );
	}

	/**
	 * Authenticate and determine if the REST request has authentication errors.
	 *
	 * @filter rest_authentication_errors
	 *
	 * @since 0.1
	 *
	 * @param mixed $result Result of any other authentication errors.
	 *
	 * @return bool|null|WP_Error
	 */
	public function authenticate( $result ) {

		// Another authentication method was used.
		if ( ! is_null( $result ) ) {
			return $result;
		}

		/**
		 * Check for REST request.
		 *
		 * @param bool $rest_request Whether or not this is a REST request.
		 */
		$rest_request = apply_filters( 'rest_authentication_is_rest_request', ( defined( 'REST_REQUEST' ) && REST_REQUEST ) );

		// This is not the authentication you're looking for.
		if ( ! $rest_request ) {
			return $result;
		}

		// Authentication is not required.
		if ( ! $this->require_token() ) {
			return $result;
		}

		// Validate the bearer token.
		$token = $this->validate_token();
		if ( is_wp_error( $token ) ) {
			return $token;
		}

		// If it's a wp_user based token, set the current user.
		if ( 'wp_user' === $token->data->user->type ) {
			wp_set_current_user( $token->data->user->id );
		}

		// Authentication succeeded.
		return true;
	}

	/**
	 * Determine if the request needs to be JWT authenticated.
	 *
	 * @since 0.1
	 *
	 * @return bool
	 */
	public function require_token() {
		$require_token  = true;
		$request_uri    = isset( $_SERVER['REQUEST_URI'] ) ? $_SERVER['REQUEST_URI'] : false; // phpcs:ignore
		$request_method = isset( $_SERVER['REQUEST_METHOD'] ) ? $_SERVER['REQUEST_METHOD'] : false; // phpcs:ignore
		$rest_uri       = self::get_rest_uri();

		// User is already authenticated.
		$user = wp_get_current_user();
		if ( isset( $user->ID ) && 0 !== $user->ID ) {
			$require_token = false;
		}

		// Only check REST API requests.
		if ( ! strpos( $request_uri, rest_get_url_prefix() ) ) {
			$require_token = false;
		}

		// GET requests do not need to be authenticated.
		if ( 'GET' === $request_method ) {
			$require_token = false;
		}

		// Don't require authentication to generate a token.
		if ( 'POST' === $request_method && $rest_uri === $request_uri ) {
			$require_token = false;
		}

		/**
		 * Filters whether a REST endpoint requires JWT authentication.
		 *
		 * @param bool   $require_token Whether a token is required.
		 * @param string $request_uri The URI which was given by the server.
		 * @param string $request_method Which request method was used to access the server.
		 */
		return apply_filters( 'rest_authentication_require_token', $require_token, $request_uri, $request_method );
	}

	/**
	 * Authenticate the user and generate a JWT token.
	 *
	 * @since 0.1
	 *
	 * @param WP_REST_Request $request The authentication request.
	 *
	 * @return array|string|WP_Error
	 */
	public function generate_token( WP_REST_Request $request ) {

		/**
		 * Authenticate the user.
		 *
		 * Regardless of the authentication method, a $user must be an object and must have
		 * an ID property to identify the user and a `type` property to identify the type of
		 * user (or wp_user will be used). As well, a data property with a `user_login` and
		 * user_email property.
		 *
		 * @param bool|object|WP_Error $user The user object, a WP_Error, or false.
		 * @param WP_REST_Request      $request The authentication request.
		 */
		$user = apply_filters( 'rest_authentication_user', false, $request );

		if ( is_wp_error( $user ) ) {
			return $user;
		}

		if ( false !== $user ) {
			if ( ! isset( $user->ID ) ) {
				return new WP_Error(
					'rest_authentication_missing_user_id',
					__( 'The user ID is missing from the user object.', 'jwt-auth' ),
					array(
						'status' => 403,
					)
				);
			}

			if ( ! isset( $user->data->user_login ) ) {
				return new WP_Error(
					'rest_authentication_missing_user_login',
					__( 'The user_login is missing from the user object.', 'jwt-auth' ),
					array(
						'status' => 403,
					)
				);
			}

			if ( ! isset( $user->data->user_email ) ) {
				return new WP_Error(
					'rest_authentication_missing_user_email',
					__( 'The user_email is missing from the user object.', 'jwt-auth' ),
					array(
						'status' => 403,
					)
				);
			}
		}

		/**
		 * If alternate method for authentication is not provided then expect a username and password.
		 */
		if ( false === $user ) {
			$username = $request->get_param( 'username' );
			$password = $request->get_param( 'password' );

			// Attempt to authenticate the WordPress user.
			$user = wp_authenticate( $username, $password );
		}

		if ( is_wp_error( $user ) ) {
			$error_code    = $user->get_error_code();
			$error_message = $user->get_error_message( $error_code );

			// Strip tags from the wp_authenticate output.
			$error_message = wp_strip_all_tags( preg_replace( '#<a.*?>.*?</a>#i', '', $error_message ), true );
			return new WP_Error(
				'rest_authentication_' . $error_code,
				$error_message,
				array(
					'status' => 403,
				)
			);
		}

		/**
		 * Determines the number of days a token will be available for processing.
		 *
		 * @param int $days Number of days. Default is `7` days.
		 */
		$days = apply_filters( 'rest_authentication_token_expire_days', 7 );
		$time = time();

		// JWT Reserved claims.
		$reserved = array(
			'iss' => get_bloginfo( 'url' ), // Token issuer.
			'iat' => $time, // Token issued at.
			'nbf' => $time, // Token accepted not before.
			'exp' => $time + ( DAY_IN_SECONDS * absint( $days ) ), // Token expiry.
		);

		// JWT Private claims.
		$private = array(
			'data' => array(
				'user' => array(
					'id'         => $user->ID,
					'type'       => isset( $user->type ) ? $user->type : 'wp_user',
					'user_login' => $user->data->user_login,
					'user_email' => $user->data->user_email,
				),
			),
		);

		/**
		 * JWT Payload.
		 *
		 * The `data` private claim will always be added, but additional claims can be added via the
		 * `rest_authentication_token_private_claims` filter. The data array will be included in the
		 * REST response, do not include sensitive user data in that array.
		 *
		 * @param array           $payload The payload used to generate the token.
		 * @param WP_User|Object  $user The authenticated user object.
		 * @param WP_REST_Request $request The authentication request.
		 */
		$payload = apply_filters(
			'rest_authentication_token_private_claims',
			array_merge( $reserved, $private ),
			$user,
			$request
		);

		// Generate JWT token.
		$token = $this->jwt( 'encode', $payload, $this->secret_key );

		/**
		 * Return response containing the JWT token and $user data.
		 *
		 * @param array           $response The REST response.
		 * @param WP_User|Object  $user The authenticated user object.
		 * @param WP_REST_Request $request The authentication request.
		 */
		return apply_filters(
			'rest_authentication_token_response',
			array(
				'access_token' => $token,
				'data'         => $payload['data'],
			),
			$user,
			$request
		);
	}

	/**
	 * Determine if a valid Bearer token has been provided.
	 *
	 * @return object|WP_Error Return the JSON Web Token object, or WP_Error on failure.
	 */
	public function validate_token() {

		// Get HTTP Authorization Header.
		$header = $this->get_auth_header();
		if ( is_wp_error( $header ) ) {
			return $header;
		}

		// Get the Bearer token from the header.
		$token = $this->get_token( $header );
		if ( is_wp_error( $token ) ) {
			return $token;
		}

		// Decode and validate the access token.
		try {

			// Decode the token.
			$jwt = $this->jwt( 'decode', $token, $this->secret_key, array( 'HS256' ) );

			// Determine if the token issuer is valid.
			$issuer_valid = $this->validate_issuer( $jwt->iss );
			if ( is_wp_error( $issuer_valid ) ) {
				return $issuer_valid;
			}

			// Determine if the token user is valid.
			$user_valid = $this->validate_user( $jwt );
			if ( is_wp_error( $user_valid ) ) {
				return $user_valid;
			}

			// Determine if the token has expired.
			$expiration_valid = $this->validate_expiration( $jwt );
			if ( is_wp_error( $expiration_valid ) ) {
				return $expiration_valid;
			}

			/**
			 * Filter response containing the JWT token.
			 *
			 * @param object $jwt The JSON Web Token or error.
			 *
			 * @return object|WP_Error
			 */
			return apply_filters( 'rest_authentication_validate_token', $jwt );
		} catch ( Exception $e ) {

			// Return exceptions as WP_Errors.
			return new WP_Error(
				'rest_authentication_token_error',
				__( 'Invalid bearer token.', 'jwt-auth' ),
				array(
					'status' => 403,
				)
			);
		}
	}

	/**
	 * Get the HTTP Authorization Header.
	 *
	 * @since 0.1
	 *
	 * @return mixed
	 */
	public function get_auth_header() {

		// Get HTTP Authorization Header.
		$header = isset( $_SERVER['HTTP_AUTHORIZATION'] ) ? $_SERVER['HTTP_AUTHORIZATION'] : false; // phpcs:ignore

		// Check for alternative header.
		if ( ! $header && isset( $_SERVER['REDIRECT_HTTP_AUTHORIZATION'] ) ) {
			$header = $_SERVER['REDIRECT_HTTP_AUTHORIZATION']; // phpcs:ignore
		}

		// The HTTP Authorization Header is missing, return an error.
		if ( ! $header ) {
			return new WP_Error(
				'rest_authentication_no_header',
				__( 'Authorization header was not found.', 'jwt-auth' ),
				array(
					'status' => 403,
				)
			);
		}

		return $header;
	}

	/**
	 * Get the Bearer token from the header.
	 *
	 * @since 0.1
	 *
	 * @param string $header The Authorization header.
	 *
	 * @return string|WP_Error
	 */
	public function get_token( $header ) {

		list( $token ) = sscanf( $header, 'Bearer %s' );

		if ( ! $token ) {
			return new WP_Error(
				'rest_authentication_no_token',
				__( 'Authentication token is missing.', 'jwt-auth' ),
				array(
					'status' => 403,
				)
			);
		}

		return $token;
	}

	/**
	 * Determine if the token issuer is valid.
	 *
	 * @since 0.1
	 *
	 * @param string $issuer Issuer of the token.
	 *
	 * @return bool|WP_Error
	 */
	public function validate_issuer( $issuer ) {

		if ( get_bloginfo( 'url' ) !== $issuer ) {
			return new WP_Error(
				'rest_authentication_invalid_token_issuer',
				__( 'Token issuer is invalid.', 'jwt-auth' ),
				array(
					'status' => 403,
				)
			);
		}

		return true;
	}

	/**
	 * Determine if the token user is valid.
	 *
	 * @since 0.1
	 *
	 * @param object $token The token.
	 *
	 * @return bool|WP_Error
	 */
	public function validate_user( $token ) {

		if ( ! isset( $token->data->user->id ) ) {
			return new WP_Error(
				'rest_authentication_missing_token_user_id',
				__( 'Token user must have an ID.', 'jwt-auth' ),
				array(
					'status' => 403,
				)
			);
		}

		if ( 'wp_user' === $token->data->user->type ) {

			$userdata = get_userdata( $token->data->user->id );

			if ( false === $userdata ) {
				return new WP_Error(
					'rest_authentication_invalid_token_wp_user',
					__( 'Token user is invalid.', 'jwt-auth' ),
					array(
						'status' => 403,
					)
				);
			}

			if ( $token->data->user->user_login !== $userdata->user_login ) {
				return new WP_Error(
					'rest_authentication_invalid_token_user_login',
					__( 'Token user_login is invalid.', 'jwt-auth' ),
					array(
						'status' => 403,
					)
				);
			}

			if ( $token->data->user->user_email !== $userdata->user_email ) {
				return new WP_Error(
					'rest_authentication_invalid_token_user_email',
					__( 'Token user_email is invalid.', 'jwt-auth' ),
					array(
						'status' => 403,
					)
				);
			}
		}

		return true;
	}

	/**
	 * Determine if the token has expired.
	 *
	 * @since 0.1
	 *
	 * @param object $token The token.
	 *
	 * @return bool|WP_Error
	 */
	public function validate_expiration( $token ) {

		if ( ! isset( $token->exp ) ) {
			return new WP_Error(
				'rest_authentication_missing_token_expiration',
				__( 'Token must have an expiration.', 'jwt-auth' ),
				array(
					'status' => 403,
				)
			);
		}

		if ( time() > $token->exp ) {
			return new WP_Error(
				'rest_authentication_token_expired',
				__( 'Token has expired.', 'jwt-auth' ),
				array(
					'status' => 403,
				)
			);
		}

		return true;
	}

	/**
	 * Performs a static method call on the JWT class for testability.
	 *
	 * @since 0.1
	 * @codeCoverageIgnore
	 *
	 * @param mixed $args Method arguments. The method name is first.
	 *
	 * @return mixed
	 */
	public function jwt( $args ) {
		$args   = func_get_args();
		$class  = get_class( new JWT() );
		$method = $args[0];
		$params = array_slice( $args, 1 );
		return call_user_func_array( $class . '::' . $method, $params );
	}
}
