<?php
// Fixture (d): nonce-ONLY ajax gate; the localize is fenced by a CUSTOM capability
// granted only to the administrator role (add_cap index) → ADMIN-ONLY → ADMIN.
add_action('wp_ajax_fixture_np_tpl', 'fixture_np_tpl');
function fixture_np_tpl() {
    check_ajax_referer('fixture_np_tpl');
    update_option('fixture_np_tpl', '1');
    wp_die();
}

add_action('admin_enqueue_scripts', 'fixture_np_tpl_assets');
function fixture_np_tpl_assets() {
    if (!current_user_can('manage_fixture_templates')) {
        return;
    }
    wp_localize_script('fixture-tpl', 'fixtureTpl', array(
        'nonce' => wp_create_nonce('fixture_np_tpl'),
    ));
}

function fixture_np_register_cap() {
    $role = get_role('administrator');
    $role->add_cap('manage_fixture_templates');
}
add_action('admin_init', 'fixture_np_register_cap');
