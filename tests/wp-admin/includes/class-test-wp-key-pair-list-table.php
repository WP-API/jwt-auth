<?php
/**
 * REST API: Tests for the Test_WP_Key_Pair_List_Table class.
 *
 * @package JWTAuth
 * @subpackage Administration
 * @since 0.1
 */

/**
 * Class Test_WP_Key_Pair_List_Table
 *
 * @since 0.1
 * @coversDefaultClass WP_Key_Pair_List_Table
 */
class Test_WP_Key_Pair_List_Table extends WP_UnitTestCase {

	/**
	 * List Table.
	 *
	 * @var WP_Key_Pair_List_Table
	 */
	protected $table;

	/**
	 * Setup.
	 *
	 * @inheritdoc
	 */
	public function setUp() {
		parent::setUp();
		$this->table = new WP_Key_Pair_List_Table( array( 'screen' => 'profile' ) );
	}

	/**
	 * Test get_columns().
	 *
	 * @covers ::get_columns()
	 */
	public function test_get_columns() {
		$expected = array(
			'name',
			'api_key',
			'created',
			'last_used',
			'last_ip',
			'token',
			'revoke',
		);
		$columns  = $this->table->get_columns();
		foreach ( $expected as $column ) {
			$this->assertArrayHasKey( $column, $columns );
		}
	}

	/**
	 * Test prepare_items().
	 *
	 * @covers ::prepare_items()
	 * @since 0.1
	 */
	public function test_prepare_items() {
		$this->table->items = array(
			array(
				'name'    => 'First',
				'api_key' => '12345',
			),
			array(
				'name'    => 'Second',
				'api_key' => '54321',
			),
		);
		$this->table->prepare_items();

		ob_start();
		$this->table->display();
		$output = ob_get_clean();

		preg_match_all( '/<tr data-api_key="(\d+)" data-name="(\S+)"[^>]*>/', $output, $matches, PREG_SET_ORDER, 0 );

		foreach ( $this->table->items as $key => $item ) {
			$this->assertEquals( $item['api_key'], $matches[ $key ][1] );
			$this->assertEquals( $item['name'], $matches[ $key ][2] );
		}
	}

	/**
	 * Test column_default().
	 *
	 * @covers ::column_default()
	 * @since 0.1
	 */
	public function test_column_default() {
		$tests = array(
			array(
				'item' => array(
					'name' => 'First',
				),
				'with' => 'name',
				'want' => 'First',
			),
			array(
				'item' => array(
					'api_key' => '12345',
				),
				'with' => 'api_key',
				'want' => '12345',
			),
			array(
				'item' => array(
					'created' => '',
				),
				'with' => 'created',
				'want' => '&mdash;',
			),
			array(
				'item' => array(
					'created' => mktime( 0, 0, 0, 2, 1, 2019 ),
				),
				'with' => 'created',
				'want' => 'February 1, 2019 12:00 am',
			),
			array(
				'item' => array(
					'last_used' => '',
				),
				'with' => 'last_used',
				'want' => '&mdash;',
			),
			array(
				'item' => array(
					'last_used' => mktime( 0, 0, 0, 2, 1, 2019 ),
				),
				'with' => 'last_used',
				'want' => 'February 1, 2019 12:00 am',
			),
			array(
				'item' => array(
					'last_ip' => '',
				),
				'with' => 'last_ip',
				'want' => '&mdash;',
			),
			array(
				'item' => array(
					'last_ip' => '127.0.0.1',
				),
				'with' => 'last_ip',
				'want' => '127.0.0.1',
			),
			array(
				'item' => array(
					'api_key' => '12345',
				),
				'with' => 'token',
				'want' => get_submit_button( 'New Token', 'secondary', 'token-key-pair-12345', false ),
			),
			array(
				'item' => array(
					'api_key' => '12345',
				),
				'with' => 'revoke',
				'want' => get_submit_button( 'Revoke', 'delete', 'revoke-key-pair-12345', false ),
			),
			array(
				'item' => array(
					'api_key' => '12345',
				),
				'with' => 'not_real',
				'want' => '',
			),
		);

		$reflection = new ReflectionClass( get_class( $this->table ) );
		$method     = $reflection->getMethod( 'column_default' );
		$method->setAccessible( true );

		foreach ( $tests as $test ) {
			$this->assertEquals( $test['want'], $method->invokeArgs( $this->table, array( $test['item'], $test['with'] ) ) );
		}
	}

	/**
	 * Test display_tablenav().
	 *
	 * @covers ::display_tablenav()
	 * @since 0.1
	 */
	public function test_display_tablenav() {
		ob_start();
		$this->table->display_tablenav( 'bottom' );
		$output = ob_get_clean();

		$this->assertContains( 'revoke-all-key-pairs', $output );
	}

	/**
	 * Test single_row().
	 *
	 * @covers ::single_row()
	 * @since 0.1
	 */
	public function test_single_row() {
		$item = array(
			'name'    => 'First',
			'api_key' => '12345',
		);

		ob_start();
		$this->table->single_row( $item );
		$output = ob_get_clean();

		preg_match_all( '/<tr data-api_key="(\d+)" data-name="(\S+)"[^>]*>/', $output, $matches, PREG_SET_ORDER, 0 );

		$this->assertEquals( $item['api_key'], $matches[0][1] );
		$this->assertEquals( $item['name'], $matches[0][2] );
	}
}
