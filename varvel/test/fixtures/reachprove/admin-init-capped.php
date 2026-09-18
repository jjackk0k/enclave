<?php
// Fixture: admin_init handler gated by manage_options — the "dead unauth candidate"
// shape from the adjudication lesson (privemap heuristic said unauth; the gate
// mechanically degrades it to ADMIN).
add_action('admin_init', 'fixture_admin_settings_save');
function fixture_admin_settings_save() {
    if (!current_user_can('manage_options')) {
        return;
    }
    if (isset($_POST['fixture_opts'])) {
        update_option('fixture_settings', $_POST['fixture_opts']);
    }
}
