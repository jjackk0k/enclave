<?php
// Fixture (b, registration side): REST route whose permission_callback is a string
// static-method reference 'PostGuard::check' — the class is defined in ANOTHER file
// (rest-static-ref-guard.php).
register_rest_route('fixture/v1', '/guarded', array(
    'methods' => 'POST',
    'callback' => 'fixture_guarded_run',
    'permission_callback' => 'PostGuard::check',
));

function fixture_guarded_run(WP_REST_Request $req) {
    return array('ok' => true);
}
