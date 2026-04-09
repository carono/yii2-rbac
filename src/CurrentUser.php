<?php

namespace carono\yii2rbac;

use yii\base\Exception;
use yii\helpers\ArrayHelper;

class CurrentUser
{

    public static $identityClass;

    /**
     * @return string|\yii\web\IdentityInterface
     * @throws Exception
     */
    private static function resolveIdentityClass(): string
    {
        $class = self::$identityClass ?? \Yii::$app->user->identityClass;
        if (!class_exists($class)) {
            throw new Exception("Identity class '$class' not found");
        }
        if (!isset(class_implements($class)['yii\web\IdentityInterface'])) {
            throw new Exception("$class must implement yii\\web\\IdentityInterface");
        }

        return $class;
    }

    /**
     * @throws Exception
     */
    public static function findUser($user)
    {
        $class = self::resolveIdentityClass();
        if (is_numeric($user)) {
            return $class::findIdentity($user);
        }
        if (is_string($user)) {
            if (!method_exists($class, 'findByUsername')) {
                throw new Exception("$class does not implement findByUsername()");
            }

            return $class::findByUsername($user);
        }
        if ($user instanceof $class) {
            return $user;
        }

        return null;
    }

    public static function getRobot($login = null)
    {
        $login = $login ?? (\Yii::$app->params['robot'] ?? null);

        return $login ? self::findUser($login) : null;
    }

    /**
     * @return \yii\web\User
     */
    public static function webUser(): \yii\web\User
    {
        return \Yii::$app->user;
    }

    public static function isGuest(): bool
    {
        return \Yii::$app->user->getIsGuest();
    }

    /**
     * @throws Exception
     */
    public static function get($asRobot = false, $robot = null)
    {
        $user = null;
        if (isset(\Yii::$app->components['user']) && !self::isGuest()) {
            $user = \Yii::$app->user->identity;
        }
        if ($asRobot && !$user) {
            $user = self::getRobot($robot);
        }

        return $user;
    }

    /**
     * @throws Exception
     */
    public static function getId($asRobot = false, $robot = null)
    {
        return ArrayHelper::getValue(self::get($asRobot, $robot), 'id');
    }

    /**
     * @throws Exception
     */
    public static function isMe($user = null): bool
    {
        $model = self::user($user);

        return $model !== null && $model->id == self::getId(true);
    }

    /**
     * @throws Exception
     */
    public static function user($user, $asRobot = true)
    {
        $model = $user !== null ? self::findUser($user) : null;

        return $model ?? self::get($asRobot);
    }

}
