<?php
// Fixture (a): ability permission_callback as a STRING static-method reference with
// a leading backslash, gate defined in the SAME file — the gosmtp/siteseo shape.
namespace Acme\Tools;

class AbilityGate {
    public static function can_manage() {
        return current_user_can('manage_options');
    }
}

wp_register_ability('acme/manage-settings', array(
    'label' => 'Manage settings',
    'execute_callback' => 'acme_manage_settings_run',
    'permission_callback' => '\Acme\Tools\AbilityGate::can_manage',
));

function acme_manage_settings_run($input) {
    update_option('acme_settings', $input);
    return array('ok' => true);
}
