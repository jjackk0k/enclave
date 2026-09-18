<?php
// Fixture (c): nonce-ONLY ajax gate, but the nonce is printed into wp_footer —
// ANY-AUTH provenance: reachability unchanged (SUBSCRIBER), evidence attached.
add_action('wp_ajax_fixture_np_public', 'fixture_np_public');
function fixture_np_public() {
    check_ajax_referer('fixture_np_public');
    update_option('fixture_np_public_hits', '1');
    wp_die();
}

add_action('wp_footer', 'fixture_np_footer');
function fixture_np_footer() {
    ?><script>window.fixtureNonce = '<?php echo wp_create_nonce('fixture_np_public'); ?>';</script><?php
}
