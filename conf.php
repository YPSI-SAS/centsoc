<?php
$moduleName = 'centsoc';
$module_conf[$moduleName] = [
    // Short module's name. Must be equal to your module's directory name
    'name' => $moduleName,
    // Full module's name
    'rname' => 'Wazuh Module',
    // Module's version
    'mod_release' => '21.04',
    // Additional information
    'infos' => 'Centreon wazuh module its a module to get information about wazuh agent.',
    // Allow your module to be uninstalled
    'is_removeable' => '1',
    // Module author's name
    'author' => 'Bertin Mélissa',
    // Stability of module.
    'stability' => 'stable',
    // Last time module was updated.
    'last_update' => '2023-05-11',
    // Release notes link, if any.
    'release_note' => '',
    // Images associated with this module.
    'images' => [
        'images/centreon.png',
    ],
];
