<?php
// Fixture (f): nonce-ONLY ajax gate; nonce localized via enqueue_block_editor_assets
// with no further guard — the block editor loads for any role with edit_posts →
// ROLE-GATED floor CONTRIBUTOR (not ADMIN).
add_action('wp_ajax_fixture_np_block', 'fixture_np_block');
function fixture_np_block() {
    check_ajax_referer('fixture_np_block');
    update_option('fixture_np_block', '1');
    wp_die();
}

add_action('enqueue_block_editor_assets', 'fixture_np_block_assets');
function fixture_np_block_assets() {
    wp_localize_script('fixture-block', 'fixtureBlock', array(
        'nonce' => wp_create_nonce('fixture_np_block'),
    ));
}
