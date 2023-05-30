
DELETE FROM `topology` WHERE `topology_page` = '333';
DELETE FROM `topology` WHERE `topology_page` = '33301';
DELETE FROM `topology` WHERE `topology_page` = '33302';
DELETE FROM `topology` WHERE `topology_page` = '33303';
DELETE FROM `topology` WHERE `topology_page` = '555';
DELETE FROM `topology` WHERE `topology_page` = '55501';


DELETE FROM `options` WHERE `key` = 'centreon_wazuh_manager_url';
DELETE FROM `options` WHERE `key` = 'centreon_wazuh_manager_user';
DELETE FROM `options` WHERE `key` = 'centreon_wazuh_manager_password';