<?php

if (!isset($centreon)) {
    exit();
}

require_once('requests.php');

$path = './modules/centreon-wazuh/';

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

$pageSize = 20;
$curPage = 1;

// Récupération des valeurs POST si il y en a
if ($_SERVER["REQUEST_METHOD"] == "POST") {
  $valeurSelectIndex = $_POST["host"];
  $pageSizeIndex = $_POST["page"];
  $severitySizeIndex = $_POST["severityFilter"];
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

// Création du menu déroulant pour le nombre d'éléments par page à afficher
$nbElementFilter = array(10,20,30,40,50,60,70,80,90,100);
$pageDefault = array($nbElementFilter[1] => 1);
if ($pageSizeIndex!==null) {
  $pageDefault = $pageSizeIndex == -1 ? array($nbElementFilter[0] => $pageSizeIndex) : array($nbElementFilter[$pageSizeIndex] => $pageSizeIndex);
  $pageSize = $pageSizeIndex == -1 ? $nbElementFilter[0] : $nbElementFilter[$pageSizeIndex];
}
$attrMapElementStatus = array(
  'defaultDataset' => $pageDefault
);
$form->addElement('select2', "page", _("Page"), $nbElementFilter, $attrMapElementStatus);


// Création du menu déroulant permettant de filtrer sur la sévérité 
$severityFilter = array("all","critical","high","medium","low","untriaged");
$severityDefault = array($severityFilter[0] => -1);
if ($severitySizeIndex!==null) {
  $severityDefault = $severitySizeIndex == -1 ? array($severityFilter[0] => $severitySizeIndex) : array($severityFilter[$severitySizeIndex] => $severitySizeIndex);
}
$attrMapSeverityStatus = array(
  'defaultDataset' => $severityDefault
);
$form->addElement('select2', "severityFilter", _("Severity"), $severityFilter, $attrMapSeverityStatus);


$values = array();
$elemArr = array();
$nbLow = 0;
$nbCritical = 0;
$nbMedium = 0;
$nbHigh = 0;
$nbUntriaged = 0;
// Si hôte sélectionné
if($valeurSelectIndex !== null){
  // Récupération des macros de l'hôte sélectionné
  $valeurSelect = $hostFilter[$valeurSelectIndex];
  $valeurSelectExplode = explode(" - ", $valeurSelect);
  $hostname = $valeurSelectExplode[1];
  $agentid = $valeurSelectExplode[0];

  // Récupération de l'ensemble des vulnérabilités de l'agent
  [$values, $status_code] = get_vulnerabilities($wazuh_url, $token, $agentid, key($severityDefault));
  if($status_code!=200){
    echo '<div class="error">' . _('Error when requesting Wazuh API. Verify Wazuh configuration. Error: '). $status_code . '</div>';
    exit();
  }
  $style = "one";
  // Calcul du nombre de vulnarabilités pour chaque sévérité
  for ($j = 0; $j < count($values); $j++) {
    switch (strtolower($values[$j]['severity'])) {
      case 'low':
        $badge = "service_ok";
        $nbLow++;
        break;
      case 'critical':
        $badge = "service_critical";
        $nbCritical++;
        break;
      case 'medium':
        $badge = "ack";
        $nbMedium++;
        break;
      case 'high':
        $badge = "service_warning";
        $nbHigh++;
        break;
      case 'untriaged':
        $badge = "service_unknown";
        $nbUntriaged++;
        break;
      
      default:
        $badge = "service_unknown";
        $nbUntriaged++;
        break;
    }

    // Ajout de l'élément dans le tableau final 
    if(strtolower(key($severityDefault)) == "all" || strtolower(key($severityDefault))==strtolower($values[$j]['severity'])){
      $elemArr[$j] = array(
        "MenuClass" => "list_" . $style,
        "RowMenu_cve" => $values[$j]['cve'],
        "RowMenu_condition" => $values[$j]['condition'],
        "RowMenu_severity" => $values[$j]['severity'],
        "RowMenu_title" => $values[$j]['title'],
        "RowMenu_type" => $values[$j]['type'],
        "RowMenu_cvss3_score" => $values[$j]['cvss3_score'],
        "RowMenu_detection" => $values[$j]['detection_time'],
        "RowMenu_badge" => $badge,
        "RowMenu_link" => "https://www.cve.org/CVERecord?id=".$values[$j]['cve']
      );
    }
    
  
    $style != "two"
      ? $style = "two"
      : $style = "one";
  }

  [$values, $status_code] = get_vulnerability_last_scan($wazuh_url, $token, $agentid);
  if($status_code!=200){
    echo '<div class="error">' . _('Error when requesting Wazuh API. Verify Wazuh configuration. Error: '). $status_code . '</div>';
    exit();
  }
  $last_full_scan = $values[0]['last_full_scan'];
  $last_partial_scan = $values[0]['last_partial_scan'];
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

$tpl->assign("lastFullScan", $last_full_scan);
$tpl->assign("lastPartialScan", $last_partial_scan);

$tpl->assign("nbCritical", $nbCritical);
$tpl->assign("nbLow", $nbLow);
$tpl->assign("nbHigh", $nbHigh);
$tpl->assign("nbUntriaged", $nbUntriaged);
$tpl->assign("nbMedium", $nbMedium);

$tpl->assign("headerMenu_cve", _("CVE"));
$tpl->assign("headerMenu_condition", _("Condition"));
$tpl->assign("headerMenu_severity", _("Severity"));
$tpl->assign("headerMenu_title", _("Title"));
$tpl->assign("headerMenu_type", _("Type"));
$tpl->assign("headerMenu_cvss3_score", _("CVSS3 Score"));
$tpl->assign("headerMenu_detection", _("Detection Time"));


$tpl->assign('form', $renderer->toArray());
$tpl->display("wazuh-cve.ihtml");

?>