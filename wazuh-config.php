<?php

if (!isset($oreon)) {
  exit();
}


$path = './modules/centreon-module-wazuh/';

$attrsTextLong = array("size" => "50");
$attrsTextVeryLong = array("size" => "200");

// Création du formulaire de configuration avec les différents champs
$form = new HTML_QuickFormCustom('Form', 'post', '?p=' . $p);
$form->addElement('header', 'title', _('Centreon Wazuh configuration'));
$form->addElement('text', 'centreon_wazuh_manager_url', _('Wazuh URL'), $attrsTextVeryLong);
$form->addElement('text', 'centreon_wazuh_manager_user', _('Wazuh user login'), $attrsTextLong);
$form->addElement('text', 'centreon_wazuh_manager_password', _('Wazuh password'), $attrsTextLong);

$form->addElement('submit', 'submitC', _("Save"));
$form->addElement('reset', 'reset', _("Reset"));

// Validation du formulaire => enregistrement des valeurs dans la DB
if ($form->validate()) {
    $values = $form->getSubmitValues();
    $queryInsert = 'UPDATE `options` SET `value` = "%s" WHERE `key` = "%s"';
    $pearDB->query(sprintf($queryInsert, $pearDB->escape($values['centreon_wazuh_manager_user']),  'centreon_wazuh_manager_user'));
    $pearDB->query(sprintf($queryInsert, $pearDB->escape($values['centreon_wazuh_manager_password']), 'centreon_wazuh_manager_password'));
    $pearDB->query(sprintf($queryInsert, $pearDB->escape($values['centreon_wazuh_manager_url']), 'centreon_wazuh_manager_url'));

}

// Récupération des valeurs par défaut
if (!isset($values)) {
  $values = array();
  $query = 'SELECT `key`, `value` FROM `options` '
      . 'WHERE `key` IN '
      . '("centreon_wazuh_manager_user", "centreon_wazuh_manager_password", "centreon_wazuh_manager_url")';
  try {
      $res = $pearDB->query($query);
  } catch (\PDOException $e) {
      // do nothing to keep same behaviour as previous version
  }
  while ($row = $res->fetch()) {
      $values[$row['key']] = $row['value'];
  }
}
$form->setDefaults($values);

/*
 *
 * Smarty template Init
 *
 */
$tpl = new Smarty();
$tpl = initSmartyTpl($path, $tpl);
$tpl->assign('p', $p);

$renderer = new HTML_QuickForm_Renderer_ArraySmarty($tpl, true);
$renderer->setRequiredTemplate('{$label}&nbsp;<font color="red" size="1">*</font>');
$renderer->setErrorTemplate('<font color="red">{$error}</font><br />{$html}');
$form->accept($renderer);
$tpl->assign('form', $renderer->toArray());
$tpl->display("wazuh-config.ihtml");

?>

