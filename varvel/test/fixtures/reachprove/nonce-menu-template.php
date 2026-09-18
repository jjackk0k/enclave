<?php
// Fixture (b, template side): top-level wp_nonce_field — guard evaluated via the
// render referrer in nonce-menu-template-reg.php, never guessed.
?>
<form method="post" action="admin-post.php">
    <input type="hidden" name="action" value="fixture_np_template_save" />
    <?php wp_nonce_field('fixture_np_template_save'); ?>
    <input type="submit" value="Save" />
</form>
