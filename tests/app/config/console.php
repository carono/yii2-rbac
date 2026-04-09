<?php

/**
 * Console application config for the test app.
 *
 * Demonstrates configuring RBAC (roles, permissions) and application routing
 * directly in console.php, as described in the README.
 */
return [
    'id'           => 'basic-console',
    'basePath'     => dirname(__DIR__),

    'controllerMap' => [
        'rbac' => [
            'class'            => 'carono\yii2rbac\RbacController',
            'removeUnusedRoles' => false,
            // Web app config files used for controller/module scanning
            'configs'          => [
                [__DIR__ . '/web.php'],
            ],
            'roles' => [
                'guest'   => null,
                'user'    => null,
                'manager' => 'user',
            ],
            'permissions' => [
                'Basic:Site:Index' => ['guest', 'user'],
                'Basic:Site:Login' => ['guest'],
                'Basic:Site:Error' => ['guest', 'user'],
                'Basic:Profile:*'  => ['user'],
            ],
        ],
    ],

    'components' => [
        'urlManager' => [
            'enablePrettyUrl' => true,
            'showScriptName'  => false,
            'rules' => [
                ''                   => 'site/index',
                'login'              => 'site/login',
                'profile/<id:\d+>'   => 'profile/index',
                'ajax/data/load'     => 'ajax/data/load',
                'ajax/data/save'     => 'ajax/data/save',
            ],
        ],
    ],
];
