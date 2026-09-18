<?php
// Fixture: REST route with an open gate (__return_true) — publicly reachable.
register_rest_route('fixture/v1', '/public-ping', array(
    'methods' => 'GET',
    'callback' => 'fixture_rest_ping',
    'permission_callback' => '__return_true',
));
function fixture_rest_ping(WP_REST_Request $req) {
    return array('pong' => true);
}
