<?php

namespace carono\yii2rbac\tests;

use carono\yii2rbac\CurrentUser;
use carono\yii2rbac\tests\support\FakeUser;
use yii\base\Exception;

class CurrentUserTest extends TestCase
{
    // -----------------------------------------------------------------
    // findUser
    // -----------------------------------------------------------------

    public function testFindUserById(): void
    {
        $user = FakeUser::make(1, 'john');
        FakeUser::seed($user);

        $this->assertSame($user, CurrentUser::findUser(1));
    }

    public function testFindUserByNumericString(): void
    {
        // is_numeric('1') = true → попадает в findIdentity, не в findByUsername
        $user = FakeUser::make(1, 'john');
        FakeUser::seed($user);

        $this->assertSame($user, CurrentUser::findUser('1'));
    }

    public function testFindUserByUsername(): void
    {
        $user = FakeUser::make(1, 'john');
        FakeUser::seed($user);

        $this->assertSame($user, CurrentUser::findUser('john'));
    }

    public function testFindUserByObject(): void
    {
        $user = FakeUser::make(1, 'john');

        $this->assertSame($user, CurrentUser::findUser($user));
    }

    public function testFindUserNotFoundReturnsNull(): void
    {
        $this->assertNull(CurrentUser::findUser(999));
    }

    public function testFindUserNullReturnsNull(): void
    {
        $this->assertNull(CurrentUser::findUser(null));
    }

    // -----------------------------------------------------------------
    // isGuest
    // -----------------------------------------------------------------

    public function testIsGuestWhenNotLoggedIn(): void
    {
        \Yii::$app->user->setIdentity(null);
        $this->assertTrue(CurrentUser::isGuest());
    }

    public function testIsGuestWhenLoggedIn(): void
    {
        $user = FakeUser::make(1, 'john');
        \Yii::$app->user->setIdentity($user);
        $this->assertFalse(CurrentUser::isGuest());
    }

    // -----------------------------------------------------------------
    // get
    // -----------------------------------------------------------------

    public function testGetReturnsNullForGuest(): void
    {
        \Yii::$app->user->setIdentity(null);
        $this->assertNull(CurrentUser::get());
    }

    public function testGetReturnsIdentityWhenLoggedIn(): void
    {
        $user = FakeUser::make(1, 'john');
        \Yii::$app->user->setIdentity($user);
        $this->assertSame($user, CurrentUser::get());
    }

    public function testGetAsRobotFallsBackWhenGuest(): void
    {
        $robot = FakeUser::make(99, 'robot');
        FakeUser::seed($robot);
        \Yii::$app->params['robot'] = 'robot';
        \Yii::$app->user->setIdentity(null);

        $this->assertSame($robot, CurrentUser::get(true));
    }

    public function testGetAsRobotDoesNotOverrideLoggedInUser(): void
    {
        $user = FakeUser::make(1, 'john');
        $robot = FakeUser::make(99, 'robot');
        FakeUser::seed($user, $robot);
        \Yii::$app->params['robot'] = 'robot';
        \Yii::$app->user->setIdentity($user);

        $result = CurrentUser::get(true);
        $this->assertSame($user, $result);
    }

    // -----------------------------------------------------------------
    // getId
    // -----------------------------------------------------------------

    public function testGetIdWhenLoggedIn(): void
    {
        $user = FakeUser::make(42, 'john');
        \Yii::$app->user->setIdentity($user);
        $this->assertEquals(42, CurrentUser::getId());
    }

    public function testGetIdWhenGuest(): void
    {
        \Yii::$app->user->setIdentity(null);
        $this->assertNull(CurrentUser::getId());
    }

    public function testGetIdAsRobotWhenGuest(): void
    {
        $robot = FakeUser::make(99, 'robot');
        FakeUser::seed($robot);
        \Yii::$app->params['robot'] = 'robot';
        \Yii::$app->user->setIdentity(null);

        $this->assertEquals(99, CurrentUser::getId(true));
    }

    // -----------------------------------------------------------------
    // getRobot
    // -----------------------------------------------------------------

    public function testGetRobotByExplicitLogin(): void
    {
        $robot = FakeUser::make(99, 'robot');
        FakeUser::seed($robot);

        $this->assertSame($robot, CurrentUser::getRobot('robot'));
    }

    public function testGetRobotFromParams(): void
    {
        $robot = FakeUser::make(99, 'robot');
        FakeUser::seed($robot);
        \Yii::$app->params['robot'] = 'robot';

        $this->assertSame($robot, CurrentUser::getRobot());
    }

    public function testGetRobotReturnsNullWhenNoParams(): void
    {
        $this->assertNull(CurrentUser::getRobot());
    }

    public function testGetRobotReturnsNullWhenNotFound(): void
    {
        $this->assertNull(CurrentUser::getRobot('unknown'));
    }

    // -----------------------------------------------------------------
    // isMe
    // -----------------------------------------------------------------

    public function testIsMeWithCurrentUser(): void
    {
        $user = FakeUser::make(1, 'john');
        FakeUser::seed($user);
        \Yii::$app->user->setIdentity($user);

        $this->assertTrue(CurrentUser::isMe(1));
    }

    public function testIsMeWithOtherUser(): void
    {
        $user1 = FakeUser::make(1, 'john');
        $user2 = FakeUser::make(2, 'jane');
        FakeUser::seed($user1, $user2);
        \Yii::$app->user->setIdentity($user1);

        $this->assertFalse(CurrentUser::isMe(2));
    }

    public function testIsMeWhenGuestReturnsFalse(): void
    {
        \Yii::$app->user->setIdentity(null);
        $this->assertFalse(CurrentUser::isMe(1));
    }

    public function testIsMeWithNullUserReturnsFalse(): void
    {
        \Yii::$app->user->setIdentity(null);
        $this->assertFalse(CurrentUser::isMe(null));
    }

    // -----------------------------------------------------------------
    // user()
    // -----------------------------------------------------------------

    public function testUserMethodReturnsFoundUser(): void
    {
        $user = FakeUser::make(5, 'alice');
        FakeUser::seed($user);

        $this->assertSame($user, CurrentUser::user(5));
    }

    public function testUserMethodFallsBackToCurrentUserWhenNullPassed(): void
    {
        $current = FakeUser::make(1, 'john');
        \Yii::$app->user->setIdentity($current);

        $this->assertSame($current, CurrentUser::user(null));
    }

    public function testUserMethodFallsBackToCurrentUserWhenNotFound(): void
    {
        $current = FakeUser::make(1, 'john');
        \Yii::$app->user->setIdentity($current);

        // ID 999 не существует → fallback на текущего пользователя
        $this->assertSame($current, CurrentUser::user(999));
    }

    public function testUserMethodFallsBackToRobotWhenGuestAndAsRobot(): void
    {
        $robot = FakeUser::make(99, 'robot');
        FakeUser::seed($robot);
        \Yii::$app->params['robot'] = 'robot';
        \Yii::$app->user->setIdentity(null);

        $result = CurrentUser::user(null, true);
        $this->assertSame($robot, $result);
    }

    public function testUserMethodReturnsNullWhenGuestAndAsRobotFalse(): void
    {
        \Yii::$app->user->setIdentity(null);

        $this->assertNull(CurrentUser::user(null, false));
    }

    // -----------------------------------------------------------------
    // webUser
    // -----------------------------------------------------------------

    public function testWebUserReturnsYiiUserComponent(): void
    {
        $this->assertSame(\Yii::$app->user, CurrentUser::webUser());
    }
}
