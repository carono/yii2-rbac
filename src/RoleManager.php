<?php

namespace carono\yii2rbac;


use yii\base\Action;
use yii\db\ActiveRecord;
use yii\helpers\ArrayHelper;
use yii\helpers\Inflector;
use yii\helpers\Url;
use yii\rbac\Permission;
use yii\rbac\Role;
use yii\web\Controller;
use yii\web\Request;

/**
 * Class RoleManager
 *
 * @package carono\yii2rbac
 */
class RoleManager
{
    public static $identityClass;
    public static $defaultApplicationId;
    public static $authManager = 'authManager';

    /**
     * @return \yii\rbac\ManagerInterface
     * @throws \Exception
     */
    public static function auth()
    {
        if (!$authManager = \Yii::$app->get(static::$authManager)) {
            throw new \Exception('Configure auth manager');
        } else {
            return $authManager;
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
        $id = null;
        if ($user instanceof ActiveRecord) {
            $id = $user->getPrimaryKey();
        } elseif (is_numeric($user)) {
            $id = $user;
        } elseif (is_null($user)) {
            $id = CurrentUser::getId();
        } elseif (is_string($user)) {
            $class = static::$identityClass ? static::$identityClass : \Yii::$app->user->identityClass;
            return static::getUserId($class::findByUsername($user));
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
        $id = static::getUserId($user);
        $roles = static::auth()->getRolesByUser($id);
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
     * @return \yii\rbac\Assignment|false
     * @throws \Exception
     */
    public static function assign($role, $user = null)
    {
        $role = static::getRole($role);
        if (!static::haveRole($role, $user)) {
            $id = static::getUserId($user);
            return static::auth()->assign($role, $id);
        } else {
            return false;
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
        if ($role instanceof Role) {
            $role = $role->name;
        }

        return in_array($role, static::getRoles($user));
    }

    /**
     * @param $roles
     * @param null $user
     * @return bool
     */
    public static function haveRoles($roles, $user = null)
    {
        return !array_diff($roles, static::getRoles($user));
    }

    /**
     * @param $roles
     * @param null $user
     * @return array
     */
    public static function haveOneOfRoles($roles, $user = null)
    {
        return array_intersect($roles, static::getRoles($user));
    }

    /**
     * @param $role
     *
     * @return bool
     */
    public static function createRole($role)
    {
        if (!static::getRole($role)) {
            return static::auth()->add(static::auth()->createRole($role));
        } else {
            return false;
        }
    }

    /**
     * @param $permission
     * @return bool
     */
    public static function add($permission)
    {
        if (is_string($permission)) {
            $permission = self::getPermission($permission);
        }
        return static::auth()->add($permission);
    }

    /**
     * @param $permission
     * @param array $params
     * @return bool
     */
    public static function updatePermissionParams($permission, $params = [])
    {
        if (is_string($permission)) {
            $permission = self::getPermission($permission);
        }
        foreach ($params as $param => $value) {
            if ($permission->canSetProperty($param)) {
                $permission->$param = $value;
            }
        }
        return self::auth()->update($permission->name, $permission);
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
            return static::auth()->getRole($role);
        }
    }

    public static function getModuleFromPermission($permission)
    {
        $arr = explode(':', $permission);
        if (count($arr) == 4) {
            return $arr[1];
        } else {
            return false;
        }
    }

    public static function getActionFromPermission($permission)
    {
        $arr = explode(':', $permission);
        if (count($arr) == 4) {
            return $arr[3];
        } elseif (count($arr) == 3) {
            return $arr[2];
        } else {
            return false;
        }
    }

    public static function getControllerFromPermission($permission)
    {
        $arr = explode(':', $permission);
        if (count($arr) == 4) {
            return $arr[2];
        } elseif (count($arr) == 3) {
            return $arr[1];
        } else {
            return false;
        }
    }

    public static function getApplicationFromPermission($permission)
    {
        $arr = explode(':', $permission);
        if (count($arr) == 4 || count($arr) == 3) {
            return $arr[0];
        } else {
            return false;
        }
    }

    /**
     * @param      $action
     *
     * @return null|string
     */
    public static function formPermissionByAction(Action $action)
    {
        $applicationId = static::$defaultApplicationId ? static::$defaultApplicationId : \Yii::$app->id;
        $module = ArrayHelper::getValue($action->controller, 'module.id', '');
        if ($module === $applicationId) {
            $module = '';
        }
        $controller = $action->controller->id;
        $name = Inflector::camelize($action->id);
        return static::formPermission($controller, $name, $module, $applicationId);
    }


    /**
     * @param        $controller
     * @param        $action
     * @param string $module
     *
     * @param null $application
     *
     * @return string
     */
    public static function formPermission($controller, $action, $module, $application = null)
    {
        if (!$application) {
            $application = \Yii::$app->id;
        }
        return join(
            ":", array_filter(
                [
                    Inflector::camelize($application),
                    Inflector::camelize($module),
                    Inflector::camelize($controller),
                    Inflector::camelize($action),
                ]
            )
        );
    }

    /**
     * @param $name
     *
     * @param array $params
     * @return bool
     */
    public static function createPermission($name, $params = [])
    {
        if (!static::getPermission($name)) {
            $permission = static::auth()->createPermission($name);
            self::updatePermissionParams($permission, $params);
            return static::auth()->add($permission);
        }

        return false;
    }

    /**
     * @param        $controller
     * @param        $action
     * @param string $module
     *
     * @param null $application
     *
     * @return bool
     */
    public static function createSitePermission($controller, $action, $module = 'Basic', $application = null)
    {
        $name = static::formPermission($controller, $action, $module, $application);
        return static::createPermission($name);
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
            return static::auth()->getPermission($permission);
        }
    }

    /**
     * @param $role
     * @param $permission
     */
    public static function addChild($role, $permission)
    {
        $role = static::getRole($role);
        $permission = static::getPermission($permission);
        if (!static::hasChild($role, $permission)) {
            static::auth()->addChild($role, $permission);
        }
    }

    /**
     * @param $role
     * @param $parent
     */
    public static function addParent($role, $parent)
    {
        $role = static::getRole($role);
        $parent = static::getRole($parent);
        if (!static::auth()->hasChild($role, $parent)) {
            static::auth()->addChild($role, $parent);
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
        $roleModel = static::getRole($role);
        $permissionModel = static::getPermission($permission);
        if (!$roleModel) {
            return false;
        }
        if (!$permissionModel) {
            return false;
        }
        return static::auth()->hasChild($roleModel, $permissionModel);
    }

    public static function urlToRoute($url)
    {
        $url = Url::to($url, true);
        $arr = parse_url($url);
        $req = new Request();
        $req->url = $arr["path"] . (isset($arr['query']) ? '?' . $arr['query'] : '');
        if (isset($arr['query'])) {
            parse_str($arr["query"], $query);
        } else {
            $query = [];
        }
        $result = \Yii::$app->urlManager->parseRequest($req);
        if ($result && empty($result[1]) && $query) {
            $result[1] = $query;
        }
        return $result;
    }

    public static function urlToPermission($url)
    {
        /* @var $controller Controller */
        if (!$route = static::urlToRoute($url)) {
            return false;
        }
        $route = static::urlToRoute($url)[0];
        $parts = \Yii::$app->createController($route);
        [$controller, $actionID] = $parts;
        if (!$controller) {
            //TODO Need trace
            return false;
        }
        if ($action = $controller->createAction($actionID)) {
            return static::formPermissionByAction($action);
        } else {
            return false;
        }
    }

    public static function checkAccessByUrl($url, $user = null)
    {
        if (!$arr = static::urlToRoute($url)) {
            return false;
        }
        $permission = static::urlToPermission($url);
        return static::checkAccess($permission, $user, $arr[1]);
    }

    /**
     * @param string|Action $permission
     * @param null $user
     *
     * @param array $params
     * @return bool
     */
    public static function checkAccess($permission, $user = null, $params = [])
    {
        if ($permission instanceof Action) {
            $permission = static::formPermissionByAction($permission);
        }
        if (CurrentUser::isGuest()) {
            return static::hasChild('guest', $permission);
        } else {
            return static::auth()->checkAccess(static::getUserId($user), $permission, $params);
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
        $role = static::getRole($role);
        $id = static::getUserId($user);
        if (static::haveRole($role, $user)) {
            return static::auth()->revoke($role, $id);
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
        return static::auth()->revokeAll(static::getUserId($user));
    }

    /**
     * @param $role
     */
    public static function removeRole($role)
    {
        $role = static::getRole($role);
        static::auth()->remove($role);
    }

    /**
     * @param $role
     */
    public static function removeChildren($role)
    {
        $role = static::getRole($role);
        static::auth()->removeChildren($role);
    }
}