/* global keyPair, confirm, wp */
( function( $, keyPair ) {
	'use strict';

	var $keyPairSection   = $( '#key-pairs-section' ),
		$newKeyPairForm     = $keyPairSection.find( '.create-key-pair' ),
		$newKeyPairField    = $newKeyPairForm.find( '.input' ),
		$newKeyPairButton   = $newKeyPairForm.find( '.button' ),
		$keyPairTwrapper    = $keyPairSection.find( '.key-pairs-list-table-wrapper' ),
		$keyPairTbody       = $keyPairTwrapper.find( 'tbody' ),
		$keyPairTrNoItems   = $keyPairTbody.find( '.no-items' ),
		$removeAllBtn       = $( '#revoke-all-key-pairs' ),
		tmplNewKeyPair      = wp.template( 'new-key-pair' ),
		tmplKeyPairRow      = wp.template( 'key-pair-row' ),
		tmplNewTokenKeyPair = wp.template( 'new-token-key-pair' );

	$newKeyPairButton.click( function( e ) {
		var name = $newKeyPairField.val();

		e.preventDefault();

		if ( 0 === name.length ) {
			$newKeyPairField.focus();
			return;
		}

		$newKeyPairField.prop( 'disabled', true );
		$newKeyPairButton.prop( 'disabled', true );

		$.ajax( {
			url: keyPair.root + '/' + keyPair.user_id,
			method: 'POST',
			beforeSend: function( xhr ) {
				xhr.setRequestHeader( 'X-WP-Nonce', keyPair.nonce );
			},
			data: {
				name: name
			}
		} ).done( function( response ) {
			$newKeyPairField.prop( 'disabled', false ).val( '' );
			$newKeyPairButton.prop( 'disabled', false );

			$newKeyPairForm.after( tmplNewKeyPair( {
				name: name,
				api_key: response.row.api_key,
				api_secret: response.api_secret
			} ) );

			$keyPairTbody.prepend( tmplKeyPairRow( response.row ) );

			$keyPairTwrapper.show();
			$keyPairTrNoItems.remove();
		} );
	} );

	$keyPairTbody.on( 'click', '.delete', function( e ) {
		var $tr   = $( e.target ).closest( 'tr' ),
			apiKey = $tr.data( 'api_key' ),
			name   = $tr.data( 'name' );

		e.preventDefault();

		if ( confirm( keyPair.text.confirm_one.replace( '%s', name ) ) ) {
			$.ajax( {
				url: keyPair.root + '/' + keyPair.user_id + '/' + apiKey + '/revoke',
				method: 'DELETE',
				beforeSend: function( xhr ) {
					xhr.setRequestHeader( 'X-WP-Nonce', keyPair.nonce );
				}
			} ).done( function( response ) {
				if ( response ) {
					if ( 0 === $tr.siblings().length ) {
						$keyPairTwrapper.hide();
					}
					$tr.remove();
				}
			} );
		}
	} );

	$keyPairTbody.on( 'click', '.token .button', function( e ) {
		var $tr   = $( e.target ).closest( 'tr' ),
			apiKey = $tr.data( 'api_key' ),
			name   = $tr.data( 'name' );

		e.preventDefault();

		$keyPairSection.after( tmplNewTokenKeyPair( {
			name: name,
			api_key: apiKey
		} ) );
	} );

	$( document ).on( 'click', '.key-pair-token', function( e ) {
		var $parent  = $( e.target ).closest( '.new-key-pair' ),
			$input    = $( 'input[name="new_token_api_secret"]' ),
			apiKey    = $parent.data( 'api_key' ),
			apiSecret = $input.val(),
			name      = $parent.data( 'name' );

		e.preventDefault();

		if ( 0 === apiSecret.length ) {
			$input.focus();
			return;
		}

		$.ajax( {
			url: keyPair.token,
			method: 'POST',
			data: {
				api_key: apiKey,
				api_secret: apiSecret
			}
		} ).done( function( response ) {
			$( '.new-key-pair.notification-dialog-wrap' ).remove();
			$keyPairSection.after( tmplNewTokenKeyPair( {
				name: name,
				api_key: apiKey,
				access_token: response.access_token,
				refresh_token: response.refresh_token
			} ) );

			$( document ).on( 'click', '.key-pair-token-download', function( event ) {
				event.preventDefault();
				downloadFile( 'token.json', response );
			} );
		} ).fail( function( jqXHR ) {
			$( '.new-key-pair.notification-dialog-wrap' ).remove();
			$keyPairSection.after( tmplNewTokenKeyPair( {
				name: name,
				api_key: apiKey,
				message: jqXHR.responseJSON.message
			} ) );
		} );
	});

	$removeAllBtn.on( 'click', function( e ) {
		e.preventDefault();

		if ( confirm( keyPair.text.confirm_all ) ) {
			$.ajax( {
				url:        keyPair.root + '/' + keyPair.user_id + '/revoke-all',
				method:     'DELETE',
				beforeSend: function( xhr ) {
					xhr.setRequestHeader( 'X-WP-Nonce', keyPair.nonce );
				}
			} ).done( function( response ) {
				if ( parseInt( response, 10 ) > 0 ) {
					$keyPairTbody.children().remove();
					$keyPairSection.children( '.new-key-pair' ).remove();
					$keyPairTwrapper.hide();
				}
			} );
		}
	} );

	$( document ).on( 'click', '.input-select', function() {
		$( this ).select();
	} );

	$( document ).on( 'click', '.key-pair-modal-dismiss', function( e ) {
		e.preventDefault();

		$( '.new-key-pair.notification-dialog-wrap' ).remove();
	} );

	$( document ).on( 'click', '.key-pair-download', function( e ) {
		e.preventDefault();
		downloadFile( 'key-pair.json', {
			api_key: $( this ).data( 'key' ),
			api_secret: $( this ).data( 'secret' )
		} );
	} );

	// If there are no items, don't display the table yet.  If there are, show it.
	if ( 0 === $keyPairTbody.children( 'tr' ).not( $keyPairTrNoItems ).length ) {
		$keyPairTwrapper.hide();
	}

	function downloadFile( $name, $object ) {
		var a = document.createElement( 'a' ),
			data = 'text/json;charset=utf-8,' + encodeURIComponent( JSON.stringify( $object ) );

		a.href = 'data:' + data;
		a.download = $name;
		document.body.appendChild( a );
		a.click();
		a.remove();
	}
} )( jQuery, keyPair );
