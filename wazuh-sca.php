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

// Vérification si c'est la page de base sans policy sélectionné
if(!isset($_GET['policy_id'])) {
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
  }

  // Création du menu déroulant pour le nombre d'elements par page à afficher
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


  $values = array();
  $elemArr = array();

  // Si hôte sélectionné
  if($valeurSelectIndex !== null){
    // Récupération des macros de l'hôte sélectionné
    $valeurSelect = $hostFilter[$valeurSelectIndex];
    $valeurSelectExplode = explode(" - ", $valeurSelect);
    $hostname = $valeurSelectExplode[1];
    $agentid = $valeurSelectExplode[0];

    // Récupération de l'ensemble des policy de l'agent
    [$values, $status_code] = get_sca($wazuh_url, $token, $agentid);
    if($status_code!=200){
      echo '<div class="error">' . _('Error when requesting Wazuh API. Verify Wazuh configuration. Error: '). $status_code . '</div>';
      exit();
    }
    $style = "one";
    // Ajout des elements dans le tableau final 
    for ($j = 0; $j < count($values); $j++) {
      $elemArr[$j] = array(
        "MenuClass" => "list_" . $style,
        "RowMenu_name" => $values[$j]['name'],
        "RowMenu_invalid" => $values[$j]['invalid'],
        "RowMenu_pass" => $values[$j]['pass'],
        "RowMenu_fail" => $values[$j]['fail'],
        "RowMenu_score" => $values[$j]['score'],
        "RowMenu_total" => $values[$j]['total_checks'],
        "RowMenu_description" => $values[$j]['description'],
        "RowMenu_scan" => $values[$j]['end_scan'],
        "RowMenu_policy_id" => $values[$j]['policy_id'],
        "RowMenu_agent_id" => $agentid,
      );
    
      $style != "two"
        ? $style = "two"
        : $style = "one";
    }
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

  $tpl->assign("headerMenu_name", _("Policy"));
  $tpl->assign("headerMenu_description", _("Description"));
  $tpl->assign("headerMenu_invalid", _("Invalid"));
  $tpl->assign("headerMenu_pass", _("Pass"));
  $tpl->assign("headerMenu_fail", _("Fail"));
  $tpl->assign("headerMenu_score", _("Score"));
  $tpl->assign("headerMenu_total", _("Total"));
  $tpl->assign("headerMenu_scan", _("End scan"));
  $tpl->assign("headerMenu_policy_id", _("Policy ID"));


  $tpl->assign('form', $renderer->toArray());
  $tpl->display("wazuh-sca.ihtml");

}else{
  // Récupération dans l'URL de l'agent id et du policy id
  $policyId = $_GET['policy_id'];
  $agentId = $_GET['agent_id'];

  // Création du formulaire de la page
  $form = new HTML_QuickFormCustom('form', 'post', "?p=".$p."&policy_id=".$policyId."&agent_id=".$agentId);
  $tpl = new Smarty();
  $tpl = initSmartyTpl($path, $tpl);
  $renderer = new HTML_QuickForm_Renderer_ArraySmarty($tpl);

  $pageSize = 20;
  $curPage = 1;

  // Récupération des valeurs POST si il y en a
  if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $pageSizeIndex = $_POST["page"];
    $resultSizeIndex = $_POST["resultFilter"];
  }

  // Création du menu déroulant permettant de filtrer sur le result
  $resultFilter = array("all","failed","passed","not applicable");
  $resultDefault = array($resultFilter[0] => -1);
  if ($resultSizeIndex!==null) {
    $resultDefault = $resultSizeIndex == -1 ? array($resultFilter[0] => $resultSizeIndex) : array($resultFilter[$resultSizeIndex] => $resultSizeIndex);
  }
  $attrMapresultStatus = array(
    'defaultDataset' => $resultDefault
  );
  $form->addElement('select2', "resultFilter", _("Result"), $resultFilter, $attrMapresultStatus);

  // Création du menu déroulant pour le nombre d'elements par page à afficher
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

  $values = array();  
  $elemArr = array();

  // Récupération du détail de la policy de l'agent sélectionné
  [$values, $status_code] = get_sca_policy($wazuh_url, $token, $agentId, $policyId, key($resultDefault));
  if($status_code!=200){
    echo '<div class="error">' . _('Error when requesting Wazuh API. Verify Wazuh configuration. Error: '). $status_code . '</div>';
    exit();
  }

  $style = "one";
  // Calcul du nombre de valeurs pour chaque result
  for ($j = 0; $j < count($values); $j++) {
    switch (strtolower($values[$j]['result'])) {
      case 'passed':
        $badge = "service_ok";
        break;
      case 'failed':
        $badge = "service_critical";
        break;
      case 'not applicable':
        $badge = "service_unknown";
        break;
      
      default:
        $badge = "service_unknown";
        break;
    }
    $remediation = str_replace ( '<', '&lt;', $values[$j]['remediation']);
    $remediation = str_replace ( '>', '&gt;', $remediation);

    $command = str_replace ( '<', '&lt;', $values[$j]['command']);
    $command = str_replace ( '>', '&gt;', $command);

    // Ajout de l'element dans le tableau final 
    $elemArr[$j] = array(
      "MenuClass" => "list_" . $style,
      "RowMenu_title" => $values[$j]['title'],
      "RowMenu_remediation" => $remediation,
      "RowMenu_command" => $command,
      "RowMenu_rationale" => $values[$j]['rationale'],
      "RowMenu_description" => $values[$j]['description'],
      "RowMenu_result" => $values[$j]['result'],
      "RowMenu_file" => $values[$j]['file'],
      "RowMenu_badge" => $badge,
    );
  
    $style != "two"
      ? $style = "two"
      : $style = "one";
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

  $tpl->assign("headerMenu_title", _("Title"));
  $tpl->assign("headerMenu_description", _("Description"));
  $tpl->assign("headerMenu_remediation", _("Remediation"));
  $tpl->assign("headerMenu_command", _("Command"));
  $tpl->assign("headerMenu_rationale", _("Rationale"));
  $tpl->assign("headerMenu_file", _("File"));
  $tpl->assign("headerMenu_result", _("Result"));

  $tpl->assign('form', $renderer->toArray());
  $tpl->display("wazuh-sca-policy.ihtml");
}

?>