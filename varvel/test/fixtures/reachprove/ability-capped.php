<?php
// Fixture: WP 6.9 Abilities API registration whose permission_callback is an inline
// closure requiring manage_options — the exact shape privemap cannot evaluate and
// the adjudication lesson flagged (admin-only in reality).
wp_register_ability('fixture/regenerate-site', array(
    'label' => 'Regenerate site content',
    'execute_callback' => 'fixture_regenerate_site',
    'permission_callback' => function () {
        return current_user_can('manage_options');
    },
    'meta' => array(
        'mcp' => array('public' => true),
        'show_in_rest' => true,
    ),
));
function fixture_regenerate_site($input) {
    update_option('fixture_regenerated', time());
    return array('done' => true);
}
