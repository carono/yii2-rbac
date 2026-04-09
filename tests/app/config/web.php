<?php

return [
    'id' => 'basic',
    'basePath' => dirname(__DIR__),
    'controllerNamespace' => 'carono\yii2rbac\tests\app\controllers',
    'modules' => [
        'ajax' => [
            'class' => 'carono\yii2rbac\tests\app\modules\ajax\AjaxModule',
        ],
    ],
];
