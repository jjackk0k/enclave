<?php
// Fixture: wp-cron scheduled-event hook — server-side only, never remote-reachable.
add_action('fixture_daily_cleanup', 'fixture_daily_cleanup_run');
function fixture_daily_cleanup_run() {
    $old = get_option('fixture_tmp_files');
    foreach ((array) $old as $f) {
        unlink($f);
    }
    update_option('fixture_last_cleanup', time());
}

function fixture_bootstrap_cron() {
    if (!wp_next_scheduled('fixture_daily_cleanup')) {
        wp_schedule_event(time(), 'daily', 'fixture_daily_cleanup');
    }
}
add_action('init', 'fixture_bootstrap_cron');
