INSERT INTO `topology` (`topology_name`, `topology_parent`, `topology_page`, `topology_order`, `topology_group`, `topology_url`, `topology_url_opt`, `is_react`)
VALUES ('Wazuh', '3', '333', '10', '1', '', NULL, '0');

INSERT INTO `topology` (`topology_name`, `topology_parent`, `topology_page`, `topology_order`, `topology_group`, `topology_url`, `topology_url_opt`, `is_react`)
VALUES ('Vulnerabilities', '333', '33301', '10', '1', './modules/centreon-module-wazuh/wazuh-cve.php', NULL, '0');

INSERT INTO `topology` (`topology_name`, `topology_parent`, `topology_page`, `topology_order`, `topology_group`, `topology_url`, `topology_url_opt`, `is_react`)
VALUES ('SCA', '333', '33302', '10', '1', './modules/centreon-module-wazuh/wazuh-sca.php', NULL, '0');

INSERT INTO `topology` (`topology_name`, `topology_parent`, `topology_page`, `topology_order`, `topology_group`, `topology_url`, `topology_url_opt`, `is_react`)
VALUES ('File integrity', '333', '33303', '10', '1', './modules/centreon-module-wazuh/wazuh-syscheck.php', NULL, '0');

INSERT INTO `topology` (`topology_name`, `topology_parent`, `topology_page`, `topology_order`, `topology_group`, `topology_url`, `topology_url_opt`, `is_react`)
VALUES ('Wazuh', '5', '555', '10', '1', './modules/centreon-module-wazuh/wazuh-config.php', NULL, '0');

INSERT INTO `topology` (`topology_name`, `topology_parent`, `topology_page`, `topology_order`, `topology_group`, `topology_url`, `topology_url_opt`, `is_react`)
VALUES ('Wazuh Configuration', '555', '55501', '10', '1', './modules/centreon-module-wazuh/wazuh-config.php', NULL, '0');

INSERT INTO `options` (`key`, `value`) VALUES ('centreon_wazuh_manager_url', 'http://localhost:55000');
INSERT INTO `options` (`key`, `value`) VALUES ('centreon_wazuh_manager_user', 'wazuh');
INSERT INTO `options` (`key`, `value`) VALUES ('centreon_wazuh_manager_password', 'wazuh');
