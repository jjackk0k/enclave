<?php
// golden-sink — goldenbench's corpus-independent POSITIVE fixture (research
// SOTA-VULN-DISCOVERY-2026-08-25.md §6 item 9): exactly one known sink — an
// unauthenticated option overwrite through admin_init with no nonce/capability
// check (the madara-core wp_manga_settings shape, minimal form).
// The manifest (data/goldenbench/manifest.json) pins this sink's ref: if you edit
// this file, keep update_option on its pinned line or update the manifest pin.
add_action( 'admin_init', 'golden_sink_save' );
function golden_sink_save() {
	if ( isset( $_POST['golden_settings'] ) ) {
		update_option( 'golden_settings', $_POST['golden_settings'] );
	}
}
