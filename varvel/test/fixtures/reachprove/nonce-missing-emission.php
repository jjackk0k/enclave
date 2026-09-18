<?php
// Fixture (e): nonce-ONLY nopriv ajax gate whose nonce action is emitted NOWHERE in
// the scanned tree — provenance unresolved: verdict unchanged (never penalized),
// note attached.
add_action('wp_ajax_nopriv_fixture_np_missing', 'fixture_np_missing');
function fixture_np_missing() {
    check_ajax_referer('fixture_np_missing_action');
    update_option('fixture_np_missing', '1');
    wp_die();
}
