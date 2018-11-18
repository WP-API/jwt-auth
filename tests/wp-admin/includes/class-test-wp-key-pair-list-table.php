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
		$table    = new WP_Key_Pair_List_Table( array( 'screen' => 'profile' ) );
		$columns  = $table->get_columns();
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
		$this->markTestIncomplete();
	}

	/**
	 * Test column_default().
	 *
	 * @covers ::column_default()
	 * @since 0.1
	 */
	public function test_column_default() {
		$this->markTestIncomplete();
	}

	/**
	 * Test display_tablenav().
	 *
	 * @covers ::display_tablenav()
	 * @since 0.1
	 */
	public function test_display_tablenav() {
		$this->markTestIncomplete();
	}

	/**
	 * Test single_row().
	 *
	 * @covers ::single_row()
	 * @since 0.1
	 */
	public function test_single_row() {
		$this->markTestIncomplete();
	}
}
