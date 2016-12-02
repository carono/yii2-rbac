<?php

namespace carono\yii2rbac;


use yii\base\Action;
use yii\db\ActiveRecord;
use yii\helpers\ArrayHelper;
use yii\helpers\Url;
use yii\rbac\Permission;
use yii\rbac\Role;
use yii\web\Request;


class RoleManager
{
    public static $userClass = 'app\models\User';
    public static $defaultApplicationId;

    /**
     * @return \yii\rbac\ManagerInterface
     * @throws \Exception
     */
    public static function auth()
    {
        if (!\Yii::$app->authManager) {
            throw new \Exception('Configure auth manager');
        } else {
            return \Yii::$app->authManager;
        }
    }

    /**
     * @param null $user
     *
     * @return int|mixed|null|string
     * @throws \Exception
     */
    private static function getUserId($user = null)
    {
        $class = self::$userClass;
        $id = null;
        if ($user instanceof ActiveRecord) {
            $id = $user->getPrimaryKey();
        } elseif (is_numeric($user)) {
            $id = $user;
        } elseif (is_null($user)) {
            $id = CurrentUser::getId();
        } elseif (is_string($user)) {
            $id = ArrayHelper::getValue($class::findByUsername($user), 'id');
        }
        return $id;
    }

    /**
     * @param null $user
     * @param bool $namesOnly
     *
     * @return array|\yii\rbac\Role[]
     * @throws \Exception
     */
    public static function getRoles($user = null, $namesOnly = true)
    {
        $id = self::getUserId($user);
        $roles = self::auth()->getRolesByUser($id);
        if ($namesOnly) {
            return array_keys($roles);
        } else {
            return $roles;
        }
    }

    /**
     * @param      $role
     * @param null $user
     *
     * @return \yii\rbac\Assignment
     * @throws \Exception
     */
    public static function assign($role, $user = null)
    {
        $role = self::getRole($role);
        if (!self::haveRole($role, $user)) {
            $id = self::getUserId($user);
            return self::auth()->assign($role, $id);
        }
    }

    /**
     * @param      $role
     * @param null $user
     *
     * @return bool
     */
    public static function haveRole($role, $user = null)
    {
        $role = self::getRole($role);
        return in_array($role, self::getRoles($user, false));
    }

    /**
     * @param $role
     *
     * @return bool
     */
    public static function createRole($role)
    {
        if (!self::getRole($role)) {
            return self::auth()->add(self::auth()->createRole($role));
        } else {
            return false;
        }
    }

    /**
     * @param $role
     *
     * @return null|Role
     */
    public static function getRole($role)
    {
        if ($role instanceof Role) {
            return $role;
        } else {
            return self::auth()->getRole($role);
        }
    }

    /**
     * @param      $action
     *
     * @return null|string
     */
    public static function formPermissionByAction(Action $action)
    {
        $applicationId = self::$defaultApplicationId ? self::$defaultApplicationId : \Yii::$app->id;
        $module = ArrayHelper::getValue($action->controller, 'module.id', $applicationId);
        $controller = $action->controller->id;
        $name = self::formName($action->id);
        return self::formPermission($controller, $name, $module, $applicationId);
    }


    /**
     * @param        $controller
     * @param        $action
     * @param string $module
     *
     * @param null   $application
     *
     * @return string
     */
    public static function formPermission($controller, $action, $module, $application = null)
    {
        if (!$application) {
            $application = \Yii::$app->id;
        }
        return join(
            ":", [
                ucwords(self::formName($application)),
                ucwords(self::formName($module)),
                ucwords(self::formName($controller)),
                ucwords(self::formName($action)),
            ]
        );
    }

    /**
     * @param $name
     *
     * @return bool
     */
    public static function createPermission($name)
    {
        if (!self::getPermission($name)) {
            $permission = self::auth()->createPermission($name);
            return self::auth()->add($permission);
        } else {
            return false;
        }
    }

    /**
     * @param        $controller
     * @param        $action
     * @param string $module
     *
     * @param null   $application
     *
     * @return bool
     */
    public static function createSitePermission($controller, $action, $module = 'Basic', $application = null)
    {
        $name = self::formPermission($controller, $action, $module, $application);
        return self::createPermission($name);
    }

    /**
     * @param $permission
     *
     * @return null|Permission
     */
    public static function getPermission($permission)
    {
        if ($permission instanceof Permission) {
            return $permission;
        } else {
            return self::auth()->getPermission($permission);
        }
    }

    /**
     * @param $role
     * @param $permission
     */
    public static function addChild($role, $permission)
    {
        $role = self::getRole($role);
        $permission = self::getPermission($permission);
        if (!self::hasChild($role, $permission)) {
            self::auth()->addChild($role, $permission);
        }
    }

    /**
     * @param $role
     * @param $parent
     */
    public static function addParent($role, $parent)
    {
        $role = self::getRole($role);
        $parent = self::getRole($parent);
        if (!self::auth()->hasChild($role, $parent)) {
            self::auth()->addChild($role, $parent);
        }
    }

    /**
     * @param $role
     *
     * @throws \Exception
     */
    public static function raiseRoleNotFound($role)
    {
        throw new \Exception("Role '$role' not found");
    }

    /**
     * @param $permission
     *
     * @throws \Exception
     */
    public static function raisePermissionNotFound($permission)
    {
        throw new \Exception("Permission '$permission' not found");
    }

    /**
     * @param $role
     * @param $permission
     *
     * @return bool
     */
    public static function hasChild($role, $permission)
    {
        $roleModel = self::getRole($role);
        $permissionModel = self::getPermission($permission);
        if (!$roleModel) {
            return false;
        }
        if (!$permissionModel) {
            return false;
        }
        return self::auth()->hasChild($roleModel, $permissionModel);
    }

    public static function formName($str)
    {
        return str_replace(' ', '', ucwords(implode(' ', explode('-', $str))));
    }

    public static function checkAccessByUrl($url, $user = null)
    {
        $url = Url::to($url, true);
        $arr = parse_url($url);
        $req = new Request();
        $req->url = $arr["path"];
        $url = \Yii::$app->urlManager->parseRequest($req);
        $arr = explode('/', $url[0]);
        if (count($arr) == 2) {
            array_unshift($arr, 'Basic');
        } elseif (count($arr) == 1) {
            array_push($arr, 'Default');
            array_push($arr, 'Index');
        }
        return self::checkAccess(self::formPermission($arr[1], $arr[2], $arr[0]), $user);
    }

    /**
     * @param      $permission
     * @param null $user
     *
     * @return bool
     * @throws \Exception
     */
    public static function checkAccess($permission, $user = null)
    {
        if ($permission instanceof Action) {
            $permission = self::formPermissionByAction($permission);
        }
        if (CurrentUser::isGuest()) {
            return self::hasChild('guest', $permission);
        } else {
            return self::auth()->checkAccess(self::getUserId($user), $permission);
        }
    }

    /**
     * @param      $role
     * @param null $user
     *
     * @return bool
     * @throws \Exception
     */
    public static function revoke($role, $user = null)
    {
        $role = self::getRole($role);
        $id = self::getUserId($user);
        if (!self::haveRole($role, $user)) {
            return self::auth()->revoke($role, $id);
        } else {
            return false;
        }
    }

    /**
     * @param null $user
     *
     * @return bool
     * @throws \Exception
     */
    public static function revokeAll($user = null)
    {
        return self::auth()->revokeAll(self::getUserId($user));
    }

    /**
     * @param $role
     */
    public static function removeRole($role)
    {
        $role = self::getRole($role);
        self::auth()->remove($role);
    }

    /**
     * @param $role
     */
    public static function removeChildren($role)
    {
        $role = self::getRole($role);
        self::auth()->removeChildren($role);
    }
}