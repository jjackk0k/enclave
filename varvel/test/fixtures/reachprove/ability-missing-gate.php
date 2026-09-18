<?php
// Fixture (c): ability permission_callback is a string static-method reference whose
// class is NOT in the scanned tree — present-but-unresolvable. Doctrine: UNCERTAIN
// with the reason named, NEVER UNAUTH (a present-but-unreadable gate is not public).
wp_register_ability('acme/external-gated', array(
    'label' => 'Externally gated',
    'execute_callback' => 'acme_external_gated_run',
    'permission_callback' => '\Missing\Vendor\Gate::check',
));

function acme_external_gated_run($input) {
    return array('ok' => true);
}
