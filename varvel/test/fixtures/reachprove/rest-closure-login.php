<?php
// Fixture: REST route gated by an inline closure checking is_user_logged_in —
// any authenticated role passes.
register_rest_route('fixture/v1', '/members', array(
    'methods' => 'POST',
    'callback' => 'fixture_rest_members',
    'permission_callback' => function () {
        return is_user_logged_in();
    },
));
function fixture_rest_members(WP_REST_Request $req) {
    return array('ok' => true);
}
