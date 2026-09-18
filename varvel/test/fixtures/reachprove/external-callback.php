<?php
// Fixture: ajax handler defined OUTSIDE the scanned tree (a library class method the
// model cannot resolve) — UNKNOWN with the reason named, never a fabricated floor.
add_action('wp_ajax_fixture_external', array('FixtureVendor\\Library\\Handlers', 'dispatch'));
