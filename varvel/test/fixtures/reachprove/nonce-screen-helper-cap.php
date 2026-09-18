<?php
// Fixture (g): nonce-ONLY ajax gate; the localize runs inside a screen-guarded
// admin enqueue (early return keyed on the admin page hook), and the screen's menu
// capability arrives through a single-helper indirection that literally returns
// 'manage_options' — the wp-maintenance-mode shape → ADMIN-ONLY → ADMIN.
add_action('wp_ajax_fixture_np_wizard', 'fixture_np_wizard');
function fixture_np_wizard() {
    if (!wp_verify_nonce($_POST['nonce'], 'fixture_np_wizard')) {
        wp_die();
    }
    update_option('fixture_np_wizard_done', '1');
    wp_die();
}

add_action('admin_menu', 'fixture_np_wizard_menu');
function fixture_np_wizard_menu() {
    add_menu_page('Fixture Wizard', 'Fixture Wizard', fixture_np_get_cap(), 'fixture-wizard', 'fixture_np_wizard_page');
}

function fixture_np_get_cap() {
    return 'manage_options';
}

function fixture_np_wizard_page() {
    echo '<h1>Wizard</h1>';
}

add_action('admin_enqueue_scripts', 'fixture_np_wizard_scripts');
function fixture_np_wizard_scripts($hook) {
    if ($hook !== 'toplevel_page_fixture-wizard') {
        return;
    }
    wp_localize_script('fixture-wizard', 'fixtureWizard', array(
        'nonce' => wp_create_nonce('fixture_np_wizard'),
    ));
}
