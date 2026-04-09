<?php

namespace carono\yii2rbac\tests;

use carono\yii2rbac\RoleManager;
use carono\yii2rbac\tests\support\FakeUser;
use yii\rbac\Role;

class RoleManagerTest extends TestCase
{
    // -----------------------------------------------------------------
    // Roles
    // -----------------------------------------------------------------

    public function testCreateRole(): void
    {
        $result = RoleManager::createRole('admin');
        $this->assertTrue($result);
        $this->assertNotNull(RoleManager::getRole('admin'));
    }

    public function testCreateRoleWithDescription(): void
    {
        RoleManager::createRole('director', ['description' => 'Директор']);
        $role = RoleManager::getRole('director');
        $this->assertEquals('Директор', $role->description);
    }

    public function testCreateRoleTwiceReturnsFalse(): void
    {
        RoleManager::createRole('admin');
        $this->assertFalse(RoleManager::createRole('admin'));
    }

    public function testGetRoleByObject(): void
    {
        RoleManager::createRole('admin');
        $role = RoleManager::getRole('admin');
        $this->assertSame($role, RoleManager::getRole($role));
    }

    public function testGetRoleNotExistsReturnsNull(): void
    {
        $this->assertNull(RoleManager::getRole('nonexistent'));
    }

    public function testRemoveRole(): void
    {
        RoleManager::createRole('temp');
        RoleManager::removeRole('temp');
        $this->assertNull(RoleManager::getRole('temp'));
    }

    // -----------------------------------------------------------------
    // Assignment
    // -----------------------------------------------------------------

    public function testAssignRole(): void
    {
        RoleManager::createRole('admin');
        RoleManager::assign('admin', 1);
        $this->assertTrue(RoleManager::haveRole('admin', 1));
    }

    public function testAssignRoleTwiceReturnsFalse(): void
    {
        RoleManager::createRole('admin');
        RoleManager::assign('admin', 1);
        $this->assertFalse(RoleManager::assign('admin', 1));
    }

    public function testAssignDoesNotAffectOtherUsers(): void
    {
        RoleManager::createRole('admin');
        RoleManager::assign('admin', 1);
        $this->assertFalse(RoleManager::haveRole('admin', 2));
    }

    public function testRevokeRole(): void
    {
        RoleManager::createRole('editor');
        RoleManager::assign('editor', 1);
        RoleManager::revoke('editor', 1);
        $this->assertFalse(RoleManager::haveRole('editor', 1));
    }

    public function testRevokeRoleNotAssignedReturnsFalse(): void
    {
        RoleManager::createRole('editor');
        $this->assertFalse(RoleManager::revoke('editor', 1));
    }

    public function testRevokeAll(): void
    {
        RoleManager::createRole('admin');
        RoleManager::createRole('editor');
        RoleManager::assign('admin', 1);
        RoleManager::assign('editor', 1);
        RoleManager::revokeAll(1);
        $this->assertEmpty(RoleManager::getRoles(1));
    }

    // -----------------------------------------------------------------
    // getRoles / haveRole / haveRoles / haveOneOfRoles
    // -----------------------------------------------------------------

    public function testGetRolesNamesOnly(): void
    {
        RoleManager::createRole('admin');
        RoleManager::createRole('editor');
        RoleManager::assign('admin', 1);
        RoleManager::assign('editor', 1);

        $roles = RoleManager::getRoles(1);
        $this->assertContains('admin', $roles);
        $this->assertContains('editor', $roles);
    }

    public function testGetRolesAsObjects(): void
    {
        RoleManager::createRole('admin');
        RoleManager::assign('admin', 1);

        $roles = RoleManager::getRoles(1, false);
        $this->assertArrayHasKey('admin', $roles);
        $this->assertInstanceOf(Role::class, $roles['admin']);
    }

    public function testGetRolesEmptyForNewUser(): void
    {
        $this->assertEmpty(RoleManager::getRoles(999));
    }

    public function testHaveRoleWithRoleObject(): void
    {
        RoleManager::createRole('admin');
        RoleManager::assign('admin', 1);
        $role = RoleManager::getRole('admin');
        $this->assertTrue(RoleManager::haveRole($role, 1));
    }

    public function testHaveRolesAllPresent(): void
    {
        RoleManager::createRole('admin');
        RoleManager::createRole('editor');
        RoleManager::assign('admin', 1);
        RoleManager::assign('editor', 1);
        $this->assertTrue(RoleManager::haveRoles(['admin', 'editor'], 1));
    }

    public function testHaveRolesMissingOne(): void
    {
        RoleManager::createRole('admin');
        RoleManager::assign('admin', 1);
        $this->assertFalse(RoleManager::haveRoles(['admin', 'editor'], 1));
    }

    public function testHaveOneOfRolesMatch(): void
    {
        RoleManager::createRole('admin');
        RoleManager::assign('admin', 1);
        $result = RoleManager::haveOneOfRoles(['admin', 'editor'], 1);
        $this->assertNotEmpty($result);
        $this->assertContains('admin', $result);
    }

    public function testHaveOneOfRolesNoMatch(): void
    {
        RoleManager::createRole('admin');
        RoleManager::assign('admin', 1);
        $this->assertEmpty(RoleManager::haveOneOfRoles(['editor', 'root'], 1));
    }

    // -----------------------------------------------------------------
    // Permissions
    // -----------------------------------------------------------------

    public function testCreatePermission(): void
    {
        $result = RoleManager::createPermission('manage-users');
        $this->assertTrue($result);
        $this->assertNotNull(RoleManager::getPermission('manage-users'));
    }

    public function testCreatePermissionWithDescription(): void
    {
        RoleManager::createPermission('manage-users', ['description' => 'Управление пользователями']);
        $perm = RoleManager::getPermission('manage-users');
        $this->assertEquals('Управление пользователями', $perm->description);
    }

    public function testCreatePermissionTwiceReturnsFalse(): void
    {
        RoleManager::createPermission('manage-users');
        $this->assertFalse(RoleManager::createPermission('manage-users'));
    }

    public function testGetPermissionByObject(): void
    {
        RoleManager::createPermission('manage-users');
        $perm = RoleManager::getPermission('manage-users');
        $this->assertSame($perm, RoleManager::getPermission($perm));
    }

    public function testGetPermissionNotExistsReturnsNull(): void
    {
        $this->assertNull(RoleManager::getPermission('nonexistent'));
    }

    public function testUpdatePermissionParams(): void
    {
        RoleManager::createPermission('some-perm');
        $perm = RoleManager::getPermission('some-perm');
        RoleManager::updatePermissionParams($perm, ['description' => 'Updated']);
        $this->assertEquals('Updated', RoleManager::getPermission('some-perm')->description);
    }

    public function testUpdatePermissionParamsByString(): void
    {
        RoleManager::createPermission('some-perm');
        RoleManager::updatePermissionParams('some-perm', ['description' => 'Via string']);
        $this->assertEquals('Via string', RoleManager::getPermission('some-perm')->description);
    }

    // -----------------------------------------------------------------
    // addChild / hasChild / addParent / removeChildren
    // -----------------------------------------------------------------

    public function testAddChild(): void
    {
        RoleManager::createRole('admin');
        RoleManager::createPermission('manage-users');
        RoleManager::addChild('admin', 'manage-users');
        $this->assertTrue(RoleManager::hasChild('admin', 'manage-users'));
    }

    public function testAddChildIdempotent(): void
    {
        RoleManager::createRole('admin');
        RoleManager::createPermission('manage-users');
        RoleManager::addChild('admin', 'manage-users');
        RoleManager::addChild('admin', 'manage-users'); // должно не упасть
        $this->assertTrue(RoleManager::hasChild('admin', 'manage-users'));
    }

    public function testHasChildReturnsFalseWhenNotAdded(): void
    {
        RoleManager::createRole('admin');
        RoleManager::createPermission('manage-users');
        $this->assertFalse(RoleManager::hasChild('admin', 'manage-users'));
    }

    public function testHasChildReturnsFalseForMissingRole(): void
    {
        RoleManager::createPermission('manage-users');
        $this->assertFalse(RoleManager::hasChild('nonexistent', 'manage-users'));
    }

    public function testHasChildReturnsFalseForMissingPermission(): void
    {
        RoleManager::createRole('admin');
        $this->assertFalse(RoleManager::hasChild('admin', 'nonexistent'));
    }

    public function testAddParent(): void
    {
        // director наследует права manager:
        // auth()->addChild(director, manager) → director включает manager
        RoleManager::createRole('manager');
        RoleManager::createRole('director');
        RoleManager::addParent('director', 'manager');

        $director = RoleManager::getRole('director');
        $manager = RoleManager::getRole('manager');
        $this->assertTrue(RoleManager::auth()->hasChild($director, $manager));
    }

    public function testAddParentIdempotent(): void
    {
        RoleManager::createRole('manager');
        RoleManager::createRole('director');
        RoleManager::addParent('director', 'manager');
        RoleManager::addParent('director', 'manager'); // не должно падать

        $director = RoleManager::getRole('director');
        $manager = RoleManager::getRole('manager');
        $this->assertTrue(RoleManager::auth()->hasChild($director, $manager));
    }

    public function testRemoveChildren(): void
    {
        RoleManager::createRole('admin');
        RoleManager::createPermission('perm1');
        RoleManager::createPermission('perm2');
        RoleManager::addChild('admin', 'perm1');
        RoleManager::addChild('admin', 'perm2');
        RoleManager::removeChildren('admin');
        $this->assertFalse(RoleManager::hasChild('admin', 'perm1'));
        $this->assertFalse(RoleManager::hasChild('admin', 'perm2'));
    }

    // -----------------------------------------------------------------
    // formPermission / parsing
    // -----------------------------------------------------------------

    public function testFormPermission3Parts(): void
    {
        // module пустой — отфильтруется, получим App:Controller:Action
        $perm = RoleManager::formPermission('site', 'index', '', 'basic');
        $this->assertEquals('Basic:Site:Index', $perm);
    }

    public function testFormPermission4Parts(): void
    {
        $perm = RoleManager::formPermission('site', 'index', 'admin', 'basic');
        $this->assertEquals('Basic:Admin:Site:Index', $perm);
    }

    public function testFormPermissionUsesAppIdWhenNoApplication(): void
    {
        // \Yii::$app->id = 'test-app' → Inflector::camelize = 'TestApp'
        $perm = RoleManager::formPermission('site', 'index', '');
        $this->assertEquals('TestApp:Site:Index', $perm);
    }

    public function testGetApplicationFromPermission3Parts(): void
    {
        $this->assertEquals('Basic', RoleManager::getApplicationFromPermission('Basic:Site:Index'));
    }

    public function testGetApplicationFromPermission4Parts(): void
    {
        $this->assertEquals('Basic', RoleManager::getApplicationFromPermission('Basic:Admin:Site:Index'));
    }

    public function testGetApplicationFromPermissionInvalid(): void
    {
        $this->assertFalse(RoleManager::getApplicationFromPermission('SiteIndex'));
    }

    public function testGetModuleFromPermission4Parts(): void
    {
        $this->assertEquals('Admin', RoleManager::getModuleFromPermission('Basic:Admin:Site:Index'));
    }

    public function testGetModuleFromPermission3Parts(): void
    {
        $this->assertFalse(RoleManager::getModuleFromPermission('Basic:Site:Index'));
    }

    public function testGetControllerFromPermission3Parts(): void
    {
        $this->assertEquals('Site', RoleManager::getControllerFromPermission('Basic:Site:Index'));
    }

    public function testGetControllerFromPermission4Parts(): void
    {
        $this->assertEquals('Site', RoleManager::getControllerFromPermission('Basic:Admin:Site:Index'));
    }

    public function testGetActionFromPermission3Parts(): void
    {
        $this->assertEquals('Index', RoleManager::getActionFromPermission('Basic:Site:Index'));
    }

    public function testGetActionFromPermission4Parts(): void
    {
        $this->assertEquals('Index', RoleManager::getActionFromPermission('Basic:Admin:Site:Index'));
    }

    public function testGetActionFromPermissionInvalid(): void
    {
        $this->assertFalse(RoleManager::getActionFromPermission('SiteIndex'));
    }

    // -----------------------------------------------------------------
    // checkAccess
    // -----------------------------------------------------------------

    public function testCheckAccessGuestAllowed(): void
    {
        RoleManager::createRole('guest');
        RoleManager::createPermission('Basic:Site:Index');
        RoleManager::addChild('guest', 'Basic:Site:Index');

        \Yii::$app->user->setIdentity(null); // гость

        $this->assertTrue(RoleManager::checkAccess('Basic:Site:Index'));
    }

    public function testCheckAccessGuestDenied(): void
    {
        RoleManager::createRole('guest');
        \Yii::$app->user->setIdentity(null);

        $this->assertFalse(RoleManager::checkAccess('Basic:Admin:Dashboard'));
    }

    public function testCheckAccessAuthenticatedUserAllowed(): void
    {
        RoleManager::createRole('user');
        RoleManager::createPermission('Basic:Profile:View');
        RoleManager::addChild('user', 'Basic:Profile:View');
        RoleManager::assign('user', 1);

        $user = FakeUser::make(1, 'john');
        FakeUser::seed($user);
        \Yii::$app->user->setIdentity($user);

        $this->assertTrue(RoleManager::checkAccess('Basic:Profile:View', 1));
    }

    public function testCheckAccessAuthenticatedUserDenied(): void
    {
        RoleManager::createRole('user');
        RoleManager::assign('user', 1);

        $user = FakeUser::make(1, 'john');
        FakeUser::seed($user);
        \Yii::$app->user->setIdentity($user);

        $this->assertFalse(RoleManager::checkAccess('Basic:Admin:Dashboard', 1));
    }

    public function testCheckAccessRoleInheritance(): void
    {
        // README: director => ['parent' => 'manager'] — director включает права manager
        RoleManager::createRole('user');
        RoleManager::createRole('manager');
        RoleManager::createPermission('Basic:Report:View');

        RoleManager::addChild('user', 'Basic:Report:View');
        RoleManager::addParent('manager', 'user'); // manager наследует user

        RoleManager::assign('manager', 2);

        $identity = FakeUser::make(2, 'manager-user');
        FakeUser::seed($identity);
        \Yii::$app->user->setIdentity($identity);

        $this->assertTrue(RoleManager::checkAccess('Basic:Report:View', 2));
    }

    public function testCheckAccessByNumericId(): void
    {
        RoleManager::createRole('admin');
        RoleManager::createPermission('Basic:Admin:Index');
        RoleManager::addChild('admin', 'Basic:Admin:Index');
        RoleManager::assign('admin', 1);

        $user = FakeUser::make(1, 'john');
        FakeUser::seed($user);
        \Yii::$app->user->setIdentity($user);

        $this->assertTrue(RoleManager::checkAccess('Basic:Admin:Index', 1));
    }
}
