<?php
// Fixture (d, definition side): the global-function gate for rest-global-fn-gate.php.
function fixture_rest_gate_fn() {
    return current_user_can('upload_files');
}
