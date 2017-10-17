<?php

namespace carono\yii2rbac;

use yii\base\InlineAction;
use yii\console\Controller;
use yii\helpers\ArrayHelper;
use yii\helpers\Console;
use yii\helpers\Inflector;
use yii\helpers\StringHelper;

class RbacController extends Controller
{
    public $identityClass;
    public $roles = [];
    public $permissions = [];
    public $permissionsByRole = [];
    public $basicId;
    public $frontendId;
    public $backendId;
    public $deny = [];
    public $cache = 'cache';

    protected $role;
    protected $user;
    protected static $configs = [];

    public function options($actionID)
    {
        return ArrayHelper::getValue(
            [
                'role-add' => ['user', 'role'],
                'role-revoke' => ['user', 'role']
            ], $actionID, []
        );
    }

    protected function getIdentityClass($config)
    {
        if (isset($config['components']['user']['identityClass'])) {
            return $config['components']['user']['identityClass'];
        } else {
            return false;
        }
    }

    public function init()
    {
        $class = null;
        if (self::isAdvanced()) {
            $b = self::getBackendConfig();
            $f = self::getFrontendConfig();
            if (!$this->identityClass) {
                if (($class = $this->getIdentityClass($b)) == $this->getIdentityClass($f)) {
                    $this->identityClass = $class;
                }
            }
            if (!$this->backendId) {
                $this->backendId = ArrayHelper::getValue($b, 'id');
            }
            if (!$this->frontendId) {
                $this->frontendId = ArrayHelper::getValue($f, 'id');
            }
        } else {
            $b = self::getBasicConfig();
            $class = $this->getIdentityClass($b);
            if (!$this->basicId) {
                $this->basicId = ArrayHelper::getValue($b, 'id');
            }
        }
        CurrentUser::$identityClass = $class;
        parent::init();
    }

    public function manageRole($assign)
    {
        if (!$this->role || !$this->user) {
            return Console::output('Run yii rbac --user=login --role=rolename');
        }
        if (!$user = CurrentUser::findUser($this->user)) {
            return Console::output("User $this->user not found");
        };
        if (!$role = RoleManager::getRole($this->role)) {
            return Console::output("Role $this->role not found");
        };
        if ($assign) {
            if (RoleManager::haveRole($role, $user)) {
                Console::output("User $this->user already have role $this->role");
            } elseif (RoleManager::assign($role, $user)) {
                Console::output("Role '$this->role' successful assigned to $this->user");
            } else {
                Console::output("Fail assign role $this->role to $this->user");
            }
        } else {
            if (!RoleManager::haveRole($role, $user)) {
                Console::output("User $this->user haven't role $this->role");
            } elseif (RoleManager::revoke($role, $user)) {
                Console::output("Role '$this->role' successful revoked from $this->user");
            } else {
                Console::output("Fail revoke role $this->role from $this->user");
            }
        }
        Console::output("Current roles: " . join('; ', RoleManager::getRoles($user)));
    }

    public function actionRoleShow()
    {
        if (!$user = CurrentUser::findUser($this->user)) {
            return Console::output("User $this->user not found");
        };
        Console::output("Current roles: " . join('; ', RoleManager::getRoles($user)));
    }

    public function actionRoleAdd()
    {
        $this->manageRole(true);
    }

    public function actionRoleRevoke()
    {
        $this->manageRole(false);
    }

    public function roles()
    {
        /*
        return [
            'guest'   => null,
            'user'    => null,
            'manager' => ['user']
        ];
        */
        return [];
    }

    public function permissions()
    {
        /*
        return [
            '*:*:*'            => ['root'],
            'Basic:Profile:*'  => ['user'],
            'Basic:Site:Login' => ['guest'],
            'Basic:Site:Index' => ['guest','user'],
            'Basic:Site:Error' => ['guest','user'],
        ];
        */
        return [];
    }


    public function actionIndex()
    {
        $roles = array_merge($this->roles, $this->roles());
        $permissions = array_merge($this->permissions, $this->permissions());
        if (!$roles && !$this->permissionsByRole) {
            return Console::output('Roles not registered, nothing to do');
        }
        if (!$permissions && !$this->permissionsByRole) {
            return Console::output('Permissions not registered, nothing to do');
        }
        $transaction = \Yii::$app->db->beginTransaction();
        foreach ($roles as $role => $parents) {
            RoleManager::createRole($role);
            RoleManager::removeChildren($role);
            if (is_array($parents)) {
                foreach ($parents as $parent) {
                    if (RoleManager::getRole($parent)) {
                        RoleManager::addParent($role, $parent);
                    }
                }
            }
        }
        foreach ($permissions as $permission => $roles1) {
            foreach ($this->normalizePermission($permission) as $name) {
                RoleManager::createPermission($name);
                foreach ($roles1 as $role) {
                    if (!RoleManager::getRole($role)){
                        Console::output("FAIL add '$name' permission for '$role'. Role '$role' not found");
                        exit;
                    }
                    RoleManager::addChild($role, $name);
                    Console::output("Set '$name' for '$role'");
                }
            }
        }

        foreach ($this->permissionsByRole as $role => $permissions) {
            foreach ($permissions as $permission) {
                foreach ($this->normalizePermission($permission) as $name) {
                    RoleManager::createPermission($name);
                    if (!RoleManager::getRole($role)){
                        Console::output("FAIL add '$name' permission for '$role'. Role '$role' not found");
                        exit;
                    }
                    RoleManager::addChild($role, $name);
                    Console::output("Set '$name' for '$role'");
                }
            }
        }

        Console::output("");
        foreach ($this->deny as $permission => $roles3) {
            foreach ($roles3 as $role) {
                RoleManager::auth()->removeChild(RoleManager::getRole($role), RoleManager::getPermission($permission));
                Console::output("Remove '$permission' for '$role'");
            }
        }

        $diffRoles = array_diff(array_keys(RoleManager::auth()->getRoles()), array_keys($roles));
        foreach ($diffRoles as $role) {
            RoleManager::removeRole($role);
        }
        $transaction->commit();
        $this->flushCache();
    }

    public function flushCache()
    {
        try {
            \Yii::$app->{$this->cache}->flush();
        } catch (\Exception $e) {
            echo "Fail clear cache: " . $e->getMessage();
        }
    }

    public function getApplicationIdByControllerClass($controller)
    {
        if (StringHelper::startsWith(get_class($controller), 'frontend')) {
            $id = $this->frontendId;
        } elseif (StringHelper::startsWith(get_class($controller), 'backend')) {
            $id = $this->backendId;
        } elseif (StringHelper::startsWith(get_class($controller), 'app')) {
            $id = $this->basicId;
        } else {
            $id = null;
        }
        return $id;
    }

    public function isRegular($expressionPermission)
    {
        if (self::isBasic()) {
            $appIds = [$this->basicId];
        } else {
            $appIds = [$this->backendId, $this->frontendId];
        }
        $appIds = array_map('yii\helpers\Inflector::camelize', $appIds);
        $appIds[] = '*';
        if (!RoleManager::getApplicationFromPermission($expressionPermission)) {
            return in_array(RoleManager::getModuleFromPermission($expressionPermission), $appIds);
        } else {
            return false;
        }
    }


    public function normalizePermission($expressionPermission)
    {
        if (strpos($expressionPermission, '*') !== false) {
            $app = RoleManager::getApplicationFromPermission($expressionPermission);
            $module = RoleManager::getModuleFromPermission($expressionPermission);
            $controller = RoleManager::getControllerFromPermission($expressionPermission);
            $action = RoleManager::getActionFromPermission($expressionPermission);

            if (!$app && self::isAdvanced() && self::isRegular($expressionPermission)) {
                $app = $module;
                $module = null;
            } elseif (!$app && self::isBasic()) {
                $app = Inflector::camelize($this->basicId);
            }
            $applications = $this->collectApplications($app);
            if (!$applications) {
                Console::output('Applications not found in expression: ' . $app);
                exit;
            }
            $modules = $this->collectModules($module, $applications);
            if (self::isRegular($expressionPermission)) {
                $controllers = $this->collectRegularControllers($controller, $applications);
            } else {
                $controllers = [];
            }
            foreach ($modules as $moduleConfig) {
                $controllers = array_merge(
                    $controllers, $this->collectControllers($controller, $moduleConfig, $applications)
                );
            }


            $actions = $this->collectActions($controllers, $action);

            $permissions = [];
            foreach ($actions as $action) {
                RoleManager::$defaultApplicationId = $this->getApplicationIdByControllerClass($action->controller);
                $permissions[] = RoleManager::formPermissionByAction($action);
            }
            return $permissions;
        } else {
            return [$expressionPermission];
        }
    }

    public function collectActions($controllers, $id)
    {
        $actions = [];
        foreach ($controllers as $controller) {
            $class = new \ReflectionClass($controller['class']);
            if ($class->isAbstract()) {
                continue;
            }
            $controller = \Yii::createObject($controller['class'], [$controller['name'], $controller['module']]);
            if ($id == "*") {
                foreach (get_class_methods($controller) as $method) {
                    if (strpos($method, 'action') === 0 && $method != "actions") {
                        $name = substr($method, 6);
                        $actions[] = new InlineAction($name, $controller, $method);
                    }
                }
                if (method_exists($controller, 'actions')) {
                    foreach ($controller->actions() as $name => $value) {
                        $actions[] = new InlineAction($name, $controller, $value);
                    }
                }
            } elseif (method_exists($controller, $method = 'action' . $id)) {
                $actions[] = new InlineAction($id, $controller, $method);
            }
        }
        return $actions;
    }

    public static function getBackendConfig()
    {
        return self::$configs['backend'] = ArrayHelper::merge(
            require(\Yii::getAlias('@common/config/main.php')),
            require(\Yii::getAlias('@common/config/main-local.php')),
            require(\Yii::getAlias('@backend/config/main.php')),
            require(\Yii::getAlias('@backend/config/main-local.php'))
        );
    }

    public static function getFrontendConfig()
    {
        return self::$configs['frontend'] = ArrayHelper::merge(
            require(\Yii::getAlias('@common/config/main.php')),
            require(\Yii::getAlias('@common/config/main-local.php')),
            require(\Yii::getAlias('@frontend/config/main.php')),
            require(\Yii::getAlias('@frontend/config/main-local.php'))
        );
    }

    public static function getBasicConfig()
    {
        return self::$configs['basic'] = require(\Yii::getAlias('@app/config/web.php'));
    }

    public static function isBasic()
    {
        return !self::isAdvanced();
    }

    public static function isAdvanced()
    {
        return key_exists('@backend', \Yii::$aliases);
    }

    public function collectRegularControllers($id, $applications = [])
    {
        $f = function ($v) {
            return [str_replace('Controller', '', basename($v, '.php')) => $v];
        };
        $f2 = function ($v) {
            return key($v);
        };
        $controllers = [];
        foreach (self::$configs as $config) {
            if (in_array(Inflector::camelize(ArrayHelper::getValue($config, 'id')), $applications)) {
                $p = str_replace('\\', '/', ArrayHelper::getValue($config, 'controllerNamespace', 'app\controllers'));
                $names = array_filter(array_map($f, glob(\Yii::getAlias("@{$p}/*Controller.php"))), $f2);
                foreach ($names as $elem) {
                    $name = key($elem);
                    $file = current($elem);
                    $className = self::extractClassByPath($file);
                    if (($id == '*' || Inflector::camelize($name) == Inflector::camelize($id))) {
                        $controllers[] = ['class' => $className, 'name' => $name, 'module' => null];
                    }
                }
            }
        }
        return $controllers;
    }

    public function collectControllers($id, $moduleConfig, $applications)
    {
        $f = function ($v) {
            return [str_replace('Controller', '', basename($v, '.php')) => $v];
        };
        $f2 = function ($v) {
            return key($v);
        };
        $controllers = [];
        $app = ArrayHelper::remove($moduleConfig[key($moduleConfig)], 'app');
        if (!in_array($app, $applications)) {
            return [];
        }
        $moduleModel = \Yii::createObject(current($moduleConfig), [key($moduleConfig), null]);
        $alias = '@' . str_replace('\\', '/', $moduleModel->controllerNamespace);
        $names = array_filter(array_map($f, glob(\Yii::getAlias($alias . "/*Controller.php"))), $f2);
        foreach ($names as $elem) {
            $name = key($elem);
            $file = current($elem);
            $className = self::extractClassByPath($file);
            $flag = $moduleModel ? StringHelper::startsWith($className, $moduleModel->controllerNamespace) : true;
            if (($id == '*' || Inflector::camelize($name) == Inflector::camelize($id)) && $flag) {
                $controllers[] = ['class' => $className, 'name' => $name, 'module' => $moduleModel];
            }
        }
        return $controllers;
    }

    public static function extractClassByPath($file)
    {
        if (file_exists($file)) {
            $content = file_get_contents($file);
            $namespace = '';
            $class = basename($file, '.php');
            if (preg_match('/namespace\s+(.+);/i', $content, $m)) {
                $namespace = $m[1];
            }
            return $namespace . '\\' . $class;
        }
        return false;
    }

    protected function extractModulesById($id)
    {
        $modules = [];
        foreach (self::$configs as $config) {
            if (Inflector::camelize(ArrayHelper::getValue($config, 'id')) == Inflector::camelize($id)) {
                $modules = ArrayHelper::getValue($config, 'modules', []);
                break;
            }
        }
        return $modules;
    }

    public function collectModules($id = '*', $applications = [])
    {
        $items = [];
        foreach ($applications as $app) {
            $items[$app] = array_merge($this->extractModulesById($app));
        }
        $result = [];
        foreach ($items as $app => $modules) {
            if (!in_array(Inflector::camelize($app), $applications)) {
                continue;
            }
            foreach ($modules as $name => $item) {
                if (is_string($item)) {
                    $item = ['class' => $item];
                }
                if ($id == '*' || Inflector::camelize($name) == Inflector::camelize($id)) {
                    $result[] = [$name => $item + ['app' => $app]];
                }
            }
        }
        return $result;
    }

    public function collectApplications($id = '*')
    {
        $result = [];
        if (self::isBasic()) {
            $result[] = Inflector::camelize($this->basicId);
        } else {
            $result[] = Inflector::camelize($this->backendId);
            $result[] = Inflector::camelize($this->frontendId);
        }
        return $id == '*' ? $result : array_intersect([Inflector::camelize($id)], $result);
    }
}
