<?php

namespace carono\yii2rbac\tests;

use carono\yii2rbac\RbacController;
use carono\yii2rbac\RoleManager;
use carono\yii2rbac\tests\support\FakeUser;

/**
 * Subclass чтобы открыть protected-свойства $role/$user для тестов.
 */
class TestableRbacController extends RbacController
{
    public $role;
    public $user;
}

class RbacControllerTest extends TestCase
{
    private TestableRbacController $cmd;

    /** Путь к конфигу тестового приложения */
    private string $webConfig;

    protected function setUp(): void
    {
        parent::setUp();

        $this->webConfig = __DIR__ . '/app/config/web.php';

        $this->cmd = new TestableRbacController('rbac', \Yii::$app);
        $this->cmd->configs = [[$this->webConfig]];
        $this->cmd->removeUnusedRoles = false; // не удалять «лишние» роли между тестами
    }

    // -----------------------------------------------------------------
    // Вспомогательные методы
    // -----------------------------------------------------------------

    /** Запускает actionIndex() без вывода в консоль. */
    private function runIndex(): void
    {
        ob_start();
        $this->cmd->actionIndex();
        ob_end_clean();
    }

    // -----------------------------------------------------------------
    // Создание ролей
    // -----------------------------------------------------------------

    public function testActionIndexCreatesRoles(): void
    {
        $this->cmd->roles = [
            'guest' => null,
            'user'  => null,
        ];
        $this->cmd->permissions = ['Basic:Site:Index' => ['guest']];

        $this->runIndex();

        $this->assertNotNull(RoleManager::getRole('guest'));
        $this->assertNotNull(RoleManager::getRole('user'));
    }

    public function testActionIndexCreatesRoleWithDescription(): void
    {
        $this->cmd->roles = [
            'director' => ['description' => 'Директор'],
        ];
        $this->cmd->permissions = ['Basic:Site:Index' => ['director']];

        $this->runIndex();

        $role = RoleManager::getRole('director');
        $this->assertEquals('Директор', $role->description);
    }

    public function testActionIndexRoleHierarchyViaStringParent(): void
    {
        // README: 'manager' => 'user' означает, что manager наследует user
        $this->cmd->roles = [
            'user'    => null,
            'manager' => 'user',
        ];
        $this->cmd->permissions = ['Basic:Site:Index' => ['user']];

        $this->runIndex();

        $manager = RoleManager::getRole('manager');
        $user    = RoleManager::getRole('user');

        // manager включает user (addParent: auth()->addChild(manager, user))
        $this->assertTrue(RoleManager::auth()->hasChild($manager, $user));
    }

    public function testActionIndexRoleHierarchyViaArrayParent(): void
    {
        // README: 'director' => ['parent' => 'manager', 'description' => 'Директор']
        $this->cmd->roles = [
            'manager'  => null,
            'director' => ['parent' => 'manager', 'description' => 'Директор'],
        ];
        $this->cmd->permissions = ['Basic:Site:Index' => ['manager']];

        $this->runIndex();

        $director = RoleManager::getRole('director');
        $manager  = RoleManager::getRole('manager');
        $this->assertTrue(RoleManager::auth()->hasChild($director, $manager));
        $this->assertEquals('Директор', $director->description);
    }

    public function testActionIndexRoleHierarchyViaIndexedArrayParents(): void
    {
        // 'role' => ['parent_a', 'parent_b'] — каждый элемент строкового списка трактуется как родитель
        $this->cmd->roles = [
            'user'    => null,
            'support' => 'user',
            'balance' => ['support'],
        ];
        $this->cmd->permissions = ['Basic:Site:Index' => ['user']];

        $this->runIndex();

        $balance = RoleManager::getRole('balance');
        $support = RoleManager::getRole('support');
        $this->assertNotNull($balance);
        $this->assertTrue(RoleManager::auth()->hasChild($balance, $support));
    }

    public function testActionIndexRoleHierarchyViaIndexedArrayMultipleParents(): void
    {
        $this->cmd->roles = [
            'user'    => null,
            'support' => 'user',
            'admin'   => 'user',
            'super'   => ['support', 'admin'],
        ];
        $this->cmd->permissions = ['Basic:Site:Index' => ['user']];

        $this->runIndex();

        $super   = RoleManager::getRole('super');
        $support = RoleManager::getRole('support');
        $admin   = RoleManager::getRole('admin');
        $this->assertTrue(RoleManager::auth()->hasChild($super, $support));
        $this->assertTrue(RoleManager::auth()->hasChild($super, $admin));
    }

    public function testRecreateRolesUpdatesHierarchy(): void
    {
        // recreateRoles пересоздаёт связи (детей), но не свойства роли.
        // Сначала создаём manager без родителя.
        RoleManager::createRole('user');
        RoleManager::createRole('manager');

        // Вызываем команду — теперь manager наследует user.
        $this->cmd->roles = [
            'user'    => null,
            'manager' => 'user',
        ];
        $this->cmd->permissions = ['Basic:Site:Index' => ['user']];
        $this->cmd->recreateRoles = true;

        $this->runIndex();

        $manager = RoleManager::getRole('manager');
        $user    = RoleManager::getRole('user');
        $this->assertTrue(RoleManager::auth()->hasChild($manager, $user));
    }

    // -----------------------------------------------------------------
    // Создание и назначение прав
    // -----------------------------------------------------------------

    public function testActionIndexCreatesExplicitPermission(): void
    {
        $this->cmd->roles = ['guest' => null];
        $this->cmd->permissions = [
            'Basic:Site:Index' => ['guest'],
            'Basic:Site:Login' => ['guest'],
        ];

        $this->runIndex();

        $this->assertNotNull(RoleManager::getPermission('Basic:Site:Index'));
        $this->assertNotNull(RoleManager::getPermission('Basic:Site:Login'));
    }

    public function testActionIndexAssignsPermissionToRole(): void
    {
        $this->cmd->roles = ['guest' => null];
        $this->cmd->permissions = ['Basic:Site:Index' => ['guest']];

        $this->runIndex();

        $this->assertTrue(RoleManager::hasChild('guest', 'Basic:Site:Index'));
    }

    public function testActionIndexAssignsPermissionToMultipleRoles(): void
    {
        $this->cmd->roles = ['guest' => null, 'user' => null];
        $this->cmd->permissions = [
            'Basic:Site:Error' => ['guest', 'user'],
        ];

        $this->runIndex();

        $this->assertTrue(RoleManager::hasChild('guest', 'Basic:Site:Error'));
        $this->assertTrue(RoleManager::hasChild('user', 'Basic:Site:Error'));
    }

    // -----------------------------------------------------------------
    // Раскрытие wildcard-шаблонов (normalizePermission)
    // -----------------------------------------------------------------

    public function testNormalizePermissionExplicit(): void
    {
        $perms = $this->cmd->normalizePermission('Basic:Site:Index');
        $this->assertEquals(['Basic:Site:Index'], $perms);
    }

    public function testNormalizePermissionExpandsControllerActions(): void
    {
        // 'Basic:Site:*' → все actions SiteController
        $perms = $this->cmd->normalizePermission('Basic:Site:*');

        $this->assertContains('Basic:Site:Index', $perms);
        $this->assertContains('Basic:Site:Login', $perms);
        $this->assertContains('Basic:Site:Error', $perms);
    }

    public function testNormalizePermissionExpandsAllControllers(): void
    {
        // 'Basic:*:*' → все controllers, все actions
        $perms = $this->cmd->normalizePermission('Basic:*:*');

        $this->assertContains('Basic:Site:Index', $perms);
        $this->assertContains('Basic:Profile:Index', $perms);
        $this->assertContains('Basic:Profile:Edit', $perms);
    }

    public function testNormalizePermissionExpandsModuleActions(): void
    {
        // 'Basic:Ajax:*:*' → все controllers в модуле Ajax
        $perms = $this->cmd->normalizePermission('Basic:Ajax:*:*');

        $this->assertContains('Basic:Ajax:Data:Load', $perms);
        $this->assertContains('Basic:Ajax:Data:Save', $perms);
    }

    public function testWildcardPermissionsCreatedInDb(): void
    {
        $this->cmd->roles = ['guest' => null];
        $this->cmd->permissions = ['Basic:Site:*' => ['guest']];

        $this->runIndex();

        $this->assertNotNull(RoleManager::getPermission('Basic:Site:Index'));
        $this->assertNotNull(RoleManager::getPermission('Basic:Site:Login'));
        $this->assertNotNull(RoleManager::getPermission('Basic:Site:Error'));
        $this->assertTrue(RoleManager::hasChild('guest', 'Basic:Site:Index'));
        $this->assertTrue(RoleManager::hasChild('guest', 'Basic:Site:Login'));
    }

    // -----------------------------------------------------------------
    // permissionsByRole
    // -----------------------------------------------------------------

    public function testPermissionsByRole(): void
    {
        $this->cmd->roles = ['admin' => null];
        $this->cmd->permissions = [];
        $this->cmd->permissionsByRole = [
            'admin' => ['manage-users', 'manage-content'],
        ];

        $this->runIndex();

        $this->assertNotNull(RoleManager::getPermission('manage-users'));
        $this->assertNotNull(RoleManager::getPermission('manage-content'));
        $this->assertTrue(RoleManager::hasChild('admin', 'manage-users'));
        $this->assertTrue(RoleManager::hasChild('admin', 'manage-content'));
    }

    // -----------------------------------------------------------------
    // removeUnusedRoles
    // -----------------------------------------------------------------

    public function testRemoveUnusedRoles(): void
    {
        // Сначала создаём роль вручную
        RoleManager::createRole('obsolete');

        $this->cmd->roles = ['admin' => null];
        $this->cmd->permissions = ['Basic:Site:Index' => ['admin']];
        $this->cmd->removeUnusedRoles = true;

        $this->runIndex();

        // Роль 'obsolete' должна быть удалена
        $this->assertNull(RoleManager::getRole('obsolete'));
        // Роль 'admin' должна остаться
        $this->assertNotNull(RoleManager::getRole('admin'));
    }

    // -----------------------------------------------------------------
    // actionRoleAdd / actionRoleRevoke
    // -----------------------------------------------------------------

    public function testActionRoleAdd(): void
    {
        RoleManager::createRole('editor');

        $user = FakeUser::make(1, 'john');
        FakeUser::seed($user);

        $this->cmd->role = 'editor';
        $this->cmd->user = 1;

        ob_start();
        $this->cmd->actionRoleAdd();
        ob_end_clean();

        $this->assertTrue(RoleManager::haveRole('editor', 1));
    }

    public function testActionRoleRevoke(): void
    {
        RoleManager::createRole('editor');
        RoleManager::assign('editor', 1);

        $user = FakeUser::make(1, 'john');
        FakeUser::seed($user);

        $this->cmd->role = 'editor';
        $this->cmd->user = 1;

        ob_start();
        $this->cmd->actionRoleRevoke();
        ob_end_clean();

        $this->assertFalse(RoleManager::haveRole('editor', 1));
    }

    public function testActionRoleAddDoesNothingIfAlreadyAssigned(): void
    {
        RoleManager::createRole('editor');
        RoleManager::assign('editor', 1);

        $user = FakeUser::make(1, 'john');
        FakeUser::seed($user);

        $this->cmd->role = 'editor';
        $this->cmd->user = 1;

        ob_start();
        $this->cmd->actionRoleAdd();
        ob_end_clean();

        // Всё ещё назначена, без ошибок
        $this->assertTrue(RoleManager::haveRole('editor', 1));
    }

    // -----------------------------------------------------------------
    // extractClassByPath
    // -----------------------------------------------------------------

    public function testExtractClassByPath(): void
    {
        $file = __DIR__ . '/app/controllers/SiteController.php';
        $class = RbacController::extractClassByPath($file);
        $this->assertEquals(
            'carono\yii2rbac\tests\app\controllers\SiteController',
            $class
        );
    }

    public function testExtractClassByPathNonExistent(): void
    {
        $this->assertFalse(RbacController::extractClassByPath('/nonexistent/file.php'));
    }

    // -----------------------------------------------------------------
    // Загрузка RBAC-конфига из console.php
    // -----------------------------------------------------------------

    /** Создаёт контроллер с consoleConfig и запускает actionIndex(). */
    private function makeConsoleConfigController(): TestableRbacController
    {
        $consoleConfig = __DIR__ . '/app/config/console.php';
        $cmd = new TestableRbacController('rbac', \Yii::$app);
        $cmd->consoleConfig = $consoleConfig;
        $cmd->removeUnusedRoles = false;
        return $cmd;
    }

    private function runIndexOn(TestableRbacController $cmd): void
    {
        ob_start();
        $cmd->actionIndex();
        ob_end_clean();
    }

    public function testConsoleConfigLoadsRoles(): void
    {
        $cmd = $this->makeConsoleConfigController();
        $this->runIndexOn($cmd);

        $this->assertNotNull(RoleManager::getRole('guest'));
        $this->assertNotNull(RoleManager::getRole('user'));
        $this->assertNotNull(RoleManager::getRole('manager'));
    }

    public function testConsoleConfigManagerInheritsUser(): void
    {
        $cmd = $this->makeConsoleConfigController();
        $this->runIndexOn($cmd);

        $manager = RoleManager::getRole('manager');
        $user    = RoleManager::getRole('user');
        $this->assertTrue(RoleManager::auth()->hasChild($manager, $user));
    }

    public function testConsoleConfigLoadsPermissions(): void
    {
        $cmd = $this->makeConsoleConfigController();
        $this->runIndexOn($cmd);

        $this->assertNotNull(RoleManager::getPermission('Basic:Site:Index'));
        $this->assertNotNull(RoleManager::getPermission('Basic:Site:Login'));
        $this->assertNotNull(RoleManager::getPermission('Basic:Site:Error'));
    }

    public function testConsoleConfigAssignsPermissionsToRoles(): void
    {
        $cmd = $this->makeConsoleConfigController();
        $this->runIndexOn($cmd);

        // Гость видит Index
        $this->assertTrue(RoleManager::hasChild('guest', 'Basic:Site:Index'));
        // Только гость — Login
        $this->assertTrue(RoleManager::hasChild('guest', 'Basic:Site:Login'));
        // Пользователь — Index
        $this->assertTrue(RoleManager::hasChild('user', 'Basic:Site:Index'));
    }

    public function testConsoleConfigExpandsWildcardPermissions(): void
    {
        $cmd = $this->makeConsoleConfigController();
        $this->runIndexOn($cmd);

        // Basic:Profile:* должен раскрыться в Index и Edit
        $this->assertNotNull(RoleManager::getPermission('Basic:Profile:Index'));
        $this->assertNotNull(RoleManager::getPermission('Basic:Profile:Edit'));
        $this->assertTrue(RoleManager::hasChild('user', 'Basic:Profile:Index'));
        $this->assertTrue(RoleManager::hasChild('user', 'Basic:Profile:Edit'));
    }

    public function testConsoleConfigPropertyOverridesFileConfig(): void
    {
        // Роли из файла: guest, user, manager.
        // Добавляем роль root прямо на объекте — она должна ДОБАВИТЬСЯ.
        $cmd = $this->makeConsoleConfigController();
        $cmd->roles = ['root' => null];

        $this->runIndexOn($cmd);

        // Роль из файла и роль из свойства — обе должны быть созданы.
        $this->assertNotNull(RoleManager::getRole('guest'));
        $this->assertNotNull(RoleManager::getRole('root'));
    }

    public function testConsoleConfigNonExistentFileIsIgnored(): void
    {
        $cmd = new TestableRbacController('rbac', \Yii::$app);
        $cmd->consoleConfig = '/nonexistent/console.php';
        $cmd->roles = ['guest' => null];
        $cmd->permissions = ['Basic:Site:Index' => ['guest']];
        $cmd->removeUnusedRoles = false;

        // Несуществующий файл не должен вызывать ошибку
        $this->runIndexOn($cmd);
        $this->assertNotNull(RoleManager::getRole('guest'));
    }
}
