<?php
// Fixture (d): REST route permission_callback as a plain global-function string —
// resolved cross-file and graded by its body.
register_rest_route('fixture/v1', '/fn-gated', array(
    'methods' => 'GET',
    'callback' => 'fixture_fn_gated_run',
    'permission_callback' => 'fixture_rest_gate_fn',
));

function fixture_fn_gated_run(WP_REST_Request $req) {
    return array('ok' => true);
}
