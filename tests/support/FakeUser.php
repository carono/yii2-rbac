<?php

namespace carono\yii2rbac\tests\support;

use yii\base\BaseObject;
use yii\web\IdentityInterface;

class FakeUser extends BaseObject implements IdentityInterface
{
    public $id;
    public $username = '';

    private static array $store = [];

    public static function make(int $id, string $username = ''): self
    {
        return new self(['id' => $id, 'username' => $username]);
    }

    public static function seed(self ...$users): void
    {
        self::$store = [];
        foreach ($users as $user) {
            self::$store[$user->id] = $user;
        }
    }

    public static function clear(): void
    {
        self::$store = [];
    }

    public static function findIdentity($id): ?self
    {
        return self::$store[$id] ?? null;
    }

    public static function findIdentityByAccessToken($token, $type = null): ?self
    {
        return null;
    }

    public static function findByUsername(string $username): ?self
    {
        foreach (self::$store as $user) {
            if ($user->username === $username) {
                return $user;
            }
        }
        return null;
    }

    public function getId()
    {
        return $this->id;
    }

    public function getAuthKey(): ?string
    {
        return null;
    }

    public function validateAuthKey($authKey): bool
    {
        return false;
    }
}
