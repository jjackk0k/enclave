<?php
// Fixture (item 5): add_action with a string static-method callback — resolution
// generalizes to hook handlers (class-oriented, cross-file in one file here).
namespace Acme\Ajax;

class StaticHandler {
    public static function run() {
        $v = $_POST['v'];
        update_option('acme_ajax_note', $v);
        wp_die();
    }
}

add_action('wp_ajax_fixture_static', '\Acme\Ajax\StaticHandler::run');
