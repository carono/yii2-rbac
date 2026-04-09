<?php

namespace carono\yii2rbac\tests;

use carono\yii2rbac\tests\support\FakeUser;
use PHPUnit\Framework\TestCase as BaseTestCase;

abstract class TestCase extends BaseTestCase
{
    protected function setUp(): void
    {
        parent::setUp();
        \Yii::$app->authManager->removeAll();
        \Yii::$app->user->setIdentity(null);
        FakeUser::clear();
        unset(\Yii::$app->params['robot']);
        \carono\yii2rbac\RoleManager::$defaultApplicationId = null;
        \carono\yii2rbac\RoleManager::$identityClass = null;
        \carono\yii2rbac\CurrentUser::$identityClass = null;
    }
}
