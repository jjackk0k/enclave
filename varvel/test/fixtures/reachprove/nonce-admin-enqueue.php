<?php
// Fixture (a): nonce-ONLY ajax gate; the nonce is localized solely inside an admin
// enqueue fenced by an early-return manage_options guard — a subscriber can never
// obtain it. Provenance ADMIN-ONLY → floor ADMIN.
add_action('wp_ajax_fixture_np_save', 'fixture_np_save');
function fixture_np_save() {
    if (!wp_verify_nonce($_POST['nonce'], 'fixture_np_save')) {
        wp_die('bad nonce');
    }
    update_option('fixture_np', sanitize_text_field($_POST['val']));
    wp_send_json_success();
}

add_action('admin_enqueue_scripts', 'fixture_np_admin_scripts');
function fixture_np_admin_scripts() {
    if (!current_user_can('manage_options')) {
        return;
    }
    wp_enqueue_script('fixture-np-admin', 'admin.js', array(), '1.0', true);
    wp_localize_script('fixture-np-admin', 'fixtureNp', array(
        'nonce' => wp_create_nonce('fixture_np_save'),
    ));
}
