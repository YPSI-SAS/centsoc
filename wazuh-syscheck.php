<?php

if (!isset($centreon)) {
    exit();
}

require_once('requests.php');

$path = './modules/centsoc/';

// Récupération des valeurs de configuration pour la connexion à l'API Wazuh
$query = 'SELECT `key`, `value` FROM `options` '
    . 'WHERE `key` IN '
    . '("centreon_wazuh_manager_user", "centreon_wazuh_manager_password", "centreon_wazuh_manager_url")';
try {
    $res = $pearDB->query($query);
} catch (\PDOException $e) {
    echo '<div class="error">' . _('Error when getting Centreon-Wazuh module options') . '</div>';
    exit();
}

while ($row = $res->fetch()) {
    if ($row['key'] == 'centreon_wazuh_manager_user') {
        $wazuh_user_login = $row['value'];
    } elseif ($row['key'] == 'centreon_wazuh_manager_password') {
        $wazuh_user_mdp = $row['value'];
    } elseif ($row['key'] == 'centreon_wazuh_manager_url') {
        $wazuh_url = $row['value'];
    }
}

// Authentification et récupération du token
[$token, $status_code] = authentication($wazuh_user_login, $wazuh_user_mdp, $wazuh_url);
if($status_code!=200){
  echo '<div class="error">' . _('Error when requesting Wazuh API. Verify Wazuh configuration. Error: '). $status_code . '</div>';
  exit();
}


// Récupération des hôtes ayant une macro HOSTWAZUHAGENTID
$valeurSelectIndex = null;
$dbResult = $pearDB->query("SELECT h.host_name, h.host_id, h.host_register, o.host_macro_value from host h join on_demand_macro_host o on h.host_id=o.host_host_id where host_register='1' and o.host_macro_name = \"\$_HOSTWAZUHAGENTID$\"");
$totalRows = $dbResult->rowCount();

// Création du formulaire de la page
$form = new HTML_QuickFormCustom('form', 'post', "?p=".$p);
$tpl = new Smarty();
$tpl = initSmartyTpl($path, $tpl);
$renderer = new HTML_QuickForm_Renderer_ArraySmarty($tpl);

$hostFilter = array();
$attrMapStatus = null;
$pageSizeIndex = null;
$typeSizeIndex = null;
$last_scan_end = null;
$last_scan_start = null;
$pageSize = 20;
$curPage = 1;
$status_code_scan = 400;

if(array_key_exists('force_scan', $_POST)) {
  $valeurSelectIndex = null;
  $status_code_scan = put_syscheck_run_scan($wazuh_url, $token);
  if($status_code_scan!=200){
    echo '<div class="error">' . _('Error when requesting Wazuh API. Verify Wazuh configuration. Error: '). $status_code_scan . '</div>';
    exit();
  }
}

if(array_key_exists('host', $_POST) || array_key_exists('page', $_POST) || array_key_exists('typeFilter', $_POST)) {
  $valeurSelectIndex = $_POST["host"];
  $pageSizeIndex = $_POST["page"];
  $typeSizeIndex = $_POST["typeFilter"];
}

// Création du menu déroulant pour les hôtes
$i = 1;
while ($group = $dbResult->fetch()) {  
  $hostFilter[$i] = $group['host_macro_value'] . " - " . $group['host_name'];
  if($i===$totalRows){
    $statusDefault = '';
    $attrMapStatus = null;
    if ($valeurSelectIndex!==null) {
      $statusDefault = array($hostFilter[$valeurSelectIndex] => $valeurSelectIndex);
    }
    $attrMapStatus = array(
        'defaultDataset' => $statusDefault
    );
    $form->addElement('select2', "host", _("Search"), $hostFilter, $attrMapStatus);
  }
  $i++;
}

// Création du menu déroulant pour le nombre d'elements par page à afficher
$nbElementFilter = array(10,20,30,40,50,60,70,80,90,100);
$pageDefault = array($nbElementFilter[1] => 1);
if ($pageSizeIndex!=null) {
  $pageDefault = $pageSizeIndex == -1 ? array($nbElementFilter[0] => $pageSizeIndex) : array($nbElementFilter[$pageSizeIndex] => $pageSizeIndex);
  $pageSize = $pageSizeIndex == -1 ? $nbElementFilter[0] : $nbElementFilter[$pageSizeIndex];
}
$attrMapElementStatus = array(
  'defaultDataset' => $pageDefault
);
$form->addElement('select2', "page", _("Page"), $nbElementFilter, $attrMapElementStatus);

// Création du menu déroulant permettant de filtrer sur le type 
$typeFilter = array("file","registry_key","registry_value");
$typeDefault = array($typeFilter[0] => -1);
if ($typeSizeIndex!=null) {
  $typeDefault = $typeSizeIndex == -1 ? array($typeFilter[0] => $typeSizeIndex) : array($typeFilter[$typeSizeIndex] => $typeSizeIndex);
}
$attrMaptypeStatus = array(
  'defaultDataset' => $typeDefault
);
$form->addElement('select2', "typeFilter", _("type"), $typeFilter, $attrMaptypeStatus);


$values = array();
$elemArr = array();
// Si hôte sélectionné
if($valeurSelectIndex != null){
  // Récupération des macros de l'hôte sélectionné
  $valeurSelect = $hostFilter[$valeurSelectIndex];
  $valeurSelectExplode = explode(" - ", $valeurSelect);
  $hostname = $valeurSelectExplode[1];
  $agentid = $valeurSelectExplode[0];

  // Récupération de l'ensemble des syscheck de l'agent
  [$values, $status_code] = get_syscheck($wazuh_url, $token, $agentid, key($typeDefault));
  if($status_code!=200){
    echo '<div class="error">' . _('Error when requesting Wazuh API. Verify Wazuh configuration. Error: '). $status_code . '</div>';
    exit();
  }
  $style = "one";

  // Ajout des elements dans le tableau final 
  for ($j = 0; $j < count($values); $j++) {
    $elemArr[$j] = array(
      "MenuClass" => "list_" . $style,
      "RowMenu_file" => $values[$j]['file'],
      "RowMenu_type" => $values[$j]['type'],
      "RowMenu_size" => $values[$j]['size'],
      "RowMenu_gname" => $values[$j]['gname'],
      "RowMenu_uname" => $values[$j]['uname'],
      "RowMenu_perm" => $values[$j]['perm'],
      "RowMenu_date" => $values[$j]['mtime'],
    );
  
    $style != "two"
      ? $style = "two"
      : $style = "one";
  }
  [$values, $status_code] = get_syscheck_last_scan($wazuh_url, $token, $agentid);
  if($status_code!=200){
    echo '<div class="error">' . _('Error when requesting Wazuh API. Verify Wazuh configuration. Error: '). $status_code . '</div>';
    exit();
  }
  $last_scan_end = $values[0]['end'];
  $last_scan_start = $values[0]['start'];

}

$elemArrLength = count($elemArr);
$nbPage = intval($elemArrLength/$pageSize + 1);

// Appel du template ihtml et passage des différentes valeurs
$attrBtnSuccess = array(
  "class" => "btc bt_success",
);
$form->addElement('submit', 'SearchB', _("Search"), $attrBtnSuccess);
$form->accept($renderer);
$tpl->assign("elemArr", $elemArr);
$tpl->assign("elemArrLength", $elemArrLength);
$tpl->assign("pageSize", $pageSize);
$tpl->assign("curPage", $curPage);
$tpl->assign("nbPage", $nbPage);
$tpl->assign("lastScanStart", $last_scan_start);
$tpl->assign("lastScanEnd", $last_scan_end);
$tpl->assign("statusCodeScan",$status_code_scan);


$tpl->assign("headerMenu_file", _("File"));
$tpl->assign("headerMenu_type", _("Type"));
$tpl->assign("headerMenu_size", _("Size (bytes)"));
$tpl->assign("headerMenu_gname", _("Group"));
$tpl->assign("headerMenu_uname", _("Owner"));
$tpl->assign("headerMenu_perm", _("Perm"));
$tpl->assign("headerMenu_date", _("Date"));


$tpl->assign('form', $renderer->toArray());
$tpl->display("wazuh-syscheck.ihtml");

?>