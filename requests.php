<?php

// Authentification à l'API Wazuh et récupération du token
function authentication($wazuh_user_login, $wazuh_user_mdp, $wazuh_url){
  $ch = curl_init();

  // Définir l'URL et les options appropriées
  curl_setopt($ch, CURLOPT_URL, $wazuh_url."/security/user/authenticate"); // URL de l'API
  curl_setopt($ch, CURLOPT_POST, 1); // Méthode POST
  curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
  curl_setopt($ch, CURLOPT_HTTPHEADER, array(
    "Authorization: Basic " . base64_encode($wazuh_user_login.":".$wazuh_user_mdp),
    "Content-Length: 0"
  ));
  curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
  curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);
  // Exécuter la requête et récupérer la réponse
  $response = curl_exec($ch);

  $status_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
  // Fermer la session cURL
  curl_close($ch);

  if($status_code == 200){
    $json = json_decode($response, true);
    $token = $json["data"]["token"];
  }
  return [$token, $status_code];
}

// Récupération des vulnérabilités sur un agent
function get_vulnerabilities($wazuh_url, $token, $agent_id, $severity){
  $ch = curl_init();
  $wazuh_url_vulnerability = $wazuh_url."/vulnerability/".$agent_id."?limit=100000&select=condition,title,cve,severity,type,cvss3_score,detection_time";
  if($severity != "all"){
    $wazuh_url_vulnerability = $wazuh_url_vulnerability . "&q=severity=" . $severity;
  }

  // Définir l'URL et les options appropriées
  curl_setopt($ch, CURLOPT_URL, $wazuh_url_vulnerability); // URL de l'API
  curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
  curl_setopt($ch, CURLOPT_HTTPHEADER, array(
    "Authorization: Bearer " . $token,
  ));
  curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
  curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);
  // Exécuter la requête et récupérer la réponse
  $response = curl_exec($ch);
  $status_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
  // Fermer la session cURL
  curl_close($ch);

  if($status_code == 200){
    $json = json_decode($response, true);
    $values = $json["data"]["affected_items"];
  }
  return [$values, $status_code];
}
// Récupération la datetime de la dernière vérification de vulnérabilité sur un agent
function get_vulnerability_last_scan($wazuh_url, $token, $agent_id){
  $ch = curl_init();
  $wazuh_url_vulnerability = $wazuh_url."/vulnerability/".$agent_id."/last_scan";
  
  // Définir l'URL et les options appropriées
  curl_setopt($ch, CURLOPT_URL, $wazuh_url_vulnerability); // URL de l'API
  curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
  curl_setopt($ch, CURLOPT_HTTPHEADER, array(
    "Authorization: Bearer " . $token,
  ));
  curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
  curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);
  // Exécuter la requête et récupérer la réponse
  $response = curl_exec($ch);
  $status_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
  // Fermer la session cURL
  curl_close($ch);

  if($status_code == 200){
    $json = json_decode($response, true);
    $values = $json["data"]["affected_items"];
  }
  return [$values, $status_code];
}

// Récupération des informations d'intégrité de fichiers sur un agent
function get_syscheck($wazuh_url, $token, $agent_id, $type){
  $ch = curl_init();
  $wazuh_url_syscheck = $wazuh_url."/syscheck/".$agent_id."?limit=100000". "&q=type=" . $type;
  
  // Définir l'URL et les options appropriées
  curl_setopt($ch, CURLOPT_URL, $wazuh_url_syscheck); // URL de l'API
  curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
  curl_setopt($ch, CURLOPT_HTTPHEADER, array(
    "Authorization: Bearer " . $token,
  ));
  curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
  curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);
  // Exécuter la requête et récupérer la réponse
  $response = curl_exec($ch);
  $status_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
  // Fermer la session cURL
  curl_close($ch);

  if($status_code == 200){
    $json = json_decode($response, true);
    $values = $json["data"]["affected_items"];
  }
  return [$values, $status_code];
}

// Récupération la datetime de la dernière vérification de syscheck sur un agent
function get_syscheck_last_scan($wazuh_url, $token, $agent_id){
  $ch = curl_init();
  $wazuh_url_syscheck = $wazuh_url."/syscheck/".$agent_id."/last_scan";
  
  // Définir l'URL et les options appropriées
  curl_setopt($ch, CURLOPT_URL, $wazuh_url_syscheck); // URL de l'API
  curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
  curl_setopt($ch, CURLOPT_HTTPHEADER, array(
    "Authorization: Bearer " . $token,
  ));
  curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
  curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);
  // Exécuter la requête et récupérer la réponse
  $response = curl_exec($ch);
  $status_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
  // Fermer la session cURL
  curl_close($ch);

  if($status_code == 200){
    $json = json_decode($response, true);
    $values = $json["data"]["affected_items"];
  }
  return [$values, $status_code];
}

// Récupération des policy sur un agent
function get_sca($wazuh_url, $token, $agent_id){
  $ch = curl_init();
  $wazuh_url_sca = $wazuh_url."/sca/".$agent_id."?limit=100000";

  // Définir l'URL et les options appropriées
  curl_setopt($ch, CURLOPT_URL, $wazuh_url_sca); // URL de l'API
  curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
  curl_setopt($ch, CURLOPT_HTTPHEADER, array(
    "Authorization: Bearer " . $token,
  ));
  curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
  curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);
  // Exécuter la requête et récupérer la réponse
  $response = curl_exec($ch);
  $status_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
  // Fermer la session cURL
  curl_close($ch);

  if($status_code == 200){
    $json = json_decode($response, true);
    $values = $json["data"]["affected_items"];
  }
  return [$values, $status_code];
}

// Récupération du détail d'une policy d'un agent
function get_sca_policy($wazuh_url, $token, $agent_id, $policy_id, $result){
  $ch = curl_init();
  $wazuh_url_sca = $wazuh_url."/sca/".$agent_id."/checks/".$policy_id."?limit=100000";
  if($result != "all"){
    $wazuh_url_sca = $wazuh_url_sca . "&q=result=" . $result;
  }
  $wazuh_url_sca = str_replace ( ' ', '%20', $wazuh_url_sca);

  // Définir l'URL et les options appropriées
  curl_setopt($ch, CURLOPT_URL, $wazuh_url_sca); // URL de l'API
  curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
  curl_setopt($ch, CURLOPT_HTTPHEADER, array(
    "Authorization: Bearer " . $token,
  ));
  curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
  curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);
  // Exécuter la requête et récupérer la réponse
  $response = curl_exec($ch);
  $status_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
  // Fermer la session cURL
  curl_close($ch);
  if($status_code == 200){
    $json = json_decode($response, true);
    $values = $json["data"]["affected_items"];
  }
  return [$values, $status_code];
}

?>