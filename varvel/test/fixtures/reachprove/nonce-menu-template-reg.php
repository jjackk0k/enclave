<?php
// Fixture (b, registration side): nonce-ONLY admin_post gate; the nonce lives at a
// template top level (nonce-menu-template.php) rendered ONLY by a manage_options
// menu page's render callback — one-level include/render association → ADMIN-ONLY.
add_action('admin_post_fixture_np_template_save', 'fixture_np_template_save');
function fixture_np_template_save() {
    if (!wp_verify_nonce($_POST['_wpnonce'], 'fixture_np_template_save')) {
        wp_die('bad nonce');
    }
    update_option('fixture_np_t', '1');
    wp_redirect(admin_url());
    exit;
}

add_action('admin_menu', 'fixture_np_menu');
function fixture_np_menu() {
    add_menu_page('Fixture NP', 'Fixture NP', 'manage_options', 'fixture-np', 'fixture_np_render_page');
}

function fixture_np_render_page() {
    include dirname(__FILE__) . '/nonce-menu-template.php';
}
