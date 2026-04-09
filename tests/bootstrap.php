<?php

defined('YII_DEBUG') or define('YII_DEBUG', true);
defined('YII_ENV') or define('YII_ENV', 'test');

require __DIR__ . '/../vendor/autoload.php';
require __DIR__ . '/../vendor/yiisoft/yii2/Yii.php';

new \yii\web\Application([
    'id' => 'test-app',
    'basePath' => __DIR__,
    'components' => [
        'db' => [
            'class' => \yii\db\Connection::class,
            'dsn' => 'mysql:host=mariadb;dbname=yii2_rbac_test;charset=utf8mb4',
            'username' => 'root',
            'password' => getenv('TEST_DB_PASSWORD') ?: '',
        ],
        'authManager' => [
            'class' => \yii\rbac\DbManager::class,
        ],
        'user' => [
            'class' => \yii\web\User::class,
            'identityClass' => \carono\yii2rbac\tests\support\FakeUser::class,
            'enableSession' => false,
            'enableAutoLogin' => false,
        ],
        'request' => [
            'class' => \yii\web\Request::class,
            'cookieValidationKey' => 'test-secret',
            'enableCsrfValidation' => false,
        ],
    ],
]);

$db = \Yii::$app->db;

// Пересоздаём таблицы при каждом запуске тестов
$db->createCommand('SET FOREIGN_KEY_CHECKS = 0')->execute();
foreach (['auth_assignment', 'auth_item_child', 'auth_item', 'auth_rule'] as $table) {
    $db->createCommand("DROP TABLE IF EXISTS `$table`")->execute();
}
$db->createCommand('SET FOREIGN_KEY_CHECKS = 1')->execute();

$db->createCommand('CREATE TABLE auth_rule (
    name VARCHAR(64) NOT NULL,
    data BLOB,
    created_at INT,
    updated_at INT,
    PRIMARY KEY (name)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4')->execute();

$db->createCommand('CREATE TABLE auth_item (
    name VARCHAR(64) NOT NULL,
    type SMALLINT NOT NULL,
    description TEXT,
    rule_name VARCHAR(64) DEFAULT NULL,
    data BLOB,
    created_at INT,
    updated_at INT,
    PRIMARY KEY (name),
    KEY idx_auth_item_type (type),
    CONSTRAINT fk_auth_item_rule FOREIGN KEY (rule_name)
        REFERENCES auth_rule (name) ON DELETE SET NULL ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4')->execute();

$db->createCommand('CREATE TABLE auth_item_child (
    parent VARCHAR(64) NOT NULL,
    child VARCHAR(64) NOT NULL,
    PRIMARY KEY (parent, child),
    CONSTRAINT fk_auth_item_child_parent FOREIGN KEY (parent)
        REFERENCES auth_item (name) ON DELETE CASCADE ON UPDATE CASCADE,
    CONSTRAINT fk_auth_item_child_child FOREIGN KEY (child)
        REFERENCES auth_item (name) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4')->execute();

// Алиас для разрешения пути к тестовым контроллерам через Yii::getAlias()
\Yii::setAlias('@carono/yii2rbac/tests', __DIR__);

$db->createCommand('CREATE TABLE auth_assignment (
    item_name VARCHAR(64) NOT NULL,
    user_id VARCHAR(64) NOT NULL,
    created_at INT,
    PRIMARY KEY (item_name, user_id),
    CONSTRAINT fk_auth_assignment_item FOREIGN KEY (item_name)
        REFERENCES auth_item (name) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4')->execute();
