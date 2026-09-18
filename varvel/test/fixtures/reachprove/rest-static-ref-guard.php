<?php
// Fixture (b, definition side): the cross-file static gate for rest-static-ref-reg.php.
namespace Acme\Guards;

class PostGuard {
    public static function check() {
        return current_user_can('edit_posts');
    }
}
