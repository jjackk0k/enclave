<?php
// Fixture: unauthenticated ajax floor (wp_ajax_nopriv_*).
add_action('wp_ajax_nopriv_fixture_ping', 'fixture_ping');
function fixture_ping() {
    $msg = $_GET['msg'];
    update_option('fixture_last_ping', $msg);
    wp_die();
}
