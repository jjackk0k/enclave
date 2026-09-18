<?php
// Fixture: authenticated-any-role ajax floor (wp_ajax_*, no gates in handler).
add_action('wp_ajax_fixture_save_note', 'fixture_save_note');
function fixture_save_note() {
    $uid = get_current_user_id();
    update_user_meta($uid, '_fixture_note', sanitize_text_field($_POST['note']));
    wp_send_json_success();
}
