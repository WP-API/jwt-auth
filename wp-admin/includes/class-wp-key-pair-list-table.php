<?php
/**
 * List Table API: WP_Key_Pair_List_Table class
 *
 * @package JWTAuth
 * @subpackage Administration
 * @since 0.1
 */

// Load the parent class if it doesn't exist.
if ( ! class_exists( 'WP_List_Table' ) ) {
	require_once ABSPATH . 'wp-admin/includes/class-wp-list-table.php';
}

/**
 * Class for displaying the list of key-pair items.
 *
 * @since 0.1
 */
class WP_Key_Pair_List_Table extends WP_List_Table {

	/**
	 * Get a list of columns.
	 *
	 * @since 0.1
	 *
	 * @return array
	 */
	public function get_columns() {
		return array(
			'name'      => esc_html__( 'Name', 'jwt-auth' ),
			'api_key'   => esc_html__( 'API Key', 'jwt-auth' ),
			'created'   => esc_html__( 'Created', 'jwt-auth' ),
			'last_used' => esc_html__( 'Last Used', 'jwt-auth' ),
			'last_ip'   => esc_html__( 'Last IP', 'jwt-auth' ),
			'token'     => esc_html__( 'Token', 'jwt-auth' ),
			'revoke'    => esc_html__( 'Revoke', 'jwt-auth' ),
		);
	}

	/**
	 * Prepares the list of items for displaying.
	 *
	 * @since 0.1
	 */
	public function prepare_items() {
		$columns  = $this->get_columns();
		$hidden   = array();
		$sortable = array();
		$primary  = 'name';

		$this->_column_headers = array( $columns, $hidden, $sortable, $primary );
	}

	/**
	 * Generates content for a single row of the table
	 *
	 * @since 0.1
	 * @access protected
	 *
	 * @param object $item The current item.
	 * @param string $column_name The current column name.
	 *
	 * @return mixed
	 */
	protected function column_default( $item, $column_name ) {
		switch ( $column_name ) {
			case 'name':
				return esc_html( $item['name'] );
			case 'api_key':
				return esc_html( $item['api_key'] );
			case 'created':
				if ( empty( $item['created'] ) ) {
					return '&mdash;';
				}
				return date( 'F j, Y g:i a', $item['created'] );
			case 'last_used':
				if ( empty( $item['last_used'] ) ) {
					return '&mdash;';
				}
				return date( 'F j, Y g:i a', $item['last_used'] );
			case 'last_ip':
				if ( empty( $item['last_ip'] ) ) {
					return '&mdash;';
				}
				return $item['last_ip'];
			case 'token':
				return get_submit_button( esc_html__( 'New Token', 'jwt-auth' ), 'secondary', 'token-key-pair-' . $item['api_key'], false );
			case 'revoke':
				return get_submit_button( esc_html__( 'Revoke', 'jwt-auth' ), 'delete', 'revoke-key-pair-' . $item['api_key'], false );
			default:
				return '';
		}
	}

	/**
	 * Replace table navigation with a revoke all key-pairs button.
	 *
	 * @since 0.1
	 * @access protected
	 *
	 * @param string $which The location of the bulk actions: 'top' or 'bottom'.
	 */
	protected function display_tablenav( $which ) {
		?>
		<div class="tablenav <?php echo esc_attr( $which ); ?>">

			<?php if ( 'bottom' === $which ) : ?>
				<div class="alignright">
					<?php submit_button( esc_html__( 'Revoke All', 'jwt-auth' ), 'delete', 'revoke-all-key-pairs', false ); ?>
				</div>
			<?php endif; ?>

			<div class="alignleft actions bulkactions">
				<?php $this->bulk_actions( $which ); ?>
			</div>
			<?php
			$this->extra_tablenav( $which );
			$this->pagination( $which );
			?>

			<br class="clear" />
		</div>
		<?php
	}

	/**
	 * Generates content for a single row of the table.
	 *
	 * @since 0.1
	 *
	 * @param object $item The current item.
	 */
	public function single_row( $item ) {
		echo '<tr data-api_key="' . esc_attr( $item['api_key'] ) . '" data-name="' . esc_attr( $item['name'] ) . '">';
		$this->single_row_columns( $item );
		echo '</tr>';
	}
}
