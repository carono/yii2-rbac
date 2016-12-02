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
    public $basicId;
    public $frontendId;
    public $backendId;

    protected $role;
    protected $user;
    protected static $configs = [];

    public function options($actionID)
    {
        return ArrayHelper::getValue(
            [
                'add-role'    => ['user', 'role'],
                'revoke-role' => ['user', 'role']
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

    public function actionAddRole()
    {
        $this->manageRole(true);
    }

    public function actionRevokeRole()
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
        if (!$roles) {
            return Console::output('Roles not registered, nothing to do');
        }
        if (!$permissions) {
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
                    RoleManager::addChild($role, $name);
                    Console::output("Set '$name' for '$role'");
                }
            }
        }
        $diffRoles = array_diff(array_keys(RoleManager::auth()->getRoles()), array_keys($roles));
        foreach ($diffRoles as $role) {
            RoleManager::removeRole($role);
        }
        $transaction->commit();
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

    public function normalizePermission($expressionPermission)
    {
        if (strpos($expressionPermission, '*') !== false) {
            $app = RoleManager::getApplicationFromPermission($expressionPermission);
            $module = RoleManager::getModuleFromPermission($expressionPermission);
            $controller = RoleManager::getControllerFromPermission($expressionPermission);
            $action = RoleManager::getActionFromPermission($expressionPermission);

            $modules = $this->collectModules($module, $app ? $app : '*');
            $controllers = $this->collectControllers($modules, $controller);
            $actions = $this->collectActions($controllers, $action);
            $permissions = [];
            foreach ($actions as $action) {
                $appId = $this->getApplicationIdByControllerClass($action->controller);
                if (RoleManager::$defaultApplicationId = $appId) {
                    $permissions[] = RoleManager::formPermissionByAction($action);
                }
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

    public static function isAdvanced()
    {
        return key_exists('@backend', \Yii::$aliases);
    }

    public function collectControllers($modules, $id)
    {
        $f = function ($v) {
            return [str_replace('Controller', '', basename($v, '.php')) => $v];
        };
        $f2 = function ($v) {
            return key($v);
        };
        $controllers = [];
        $moduleModel = null;
        foreach ($modules as $module) {
            if ($module) {
                $moduleModel = \Yii::createObject(current($module), [key($module), null]);
                $alias = '@' . str_replace('\\', '/', $moduleModel->controllerNamespace);
                $names = array_map(
                    $f, glob(\Yii::getAlias($alias . "/*Controller.php"))
                );
            } else {
                $backend = $frontend = $basic = [];
                if (self::isAdvanced()) {
                    $backend = array_map($f, glob(\Yii::getAlias('@backend/controllers/*Controller.php')));
                    $frontend = array_map($f, glob(\Yii::getAlias('@frontend/controllers/*Controller.php')));
                } else {
                    $basic = array_map($f, glob(\Yii::getAlias('@app/controllers/*Controller.php')));
                }
                $names = array_merge($backend, $frontend, $basic);
            }
            foreach (array_filter($names, $f2) as $elem) {
                $name = key($elem);
                $file = current($elem);
                $className = self::extractClassByPath($file);
                $flag = $moduleModel ? StringHelper::startsWith($className, $moduleModel->controllerNamespace) : true;
                if (($id == '*' || Inflector::camelize($name) == Inflector::camelize($id)) && $flag) {
                    $controllers[] = ['class' => $className, 'name' => $name, 'module' => $moduleModel];
                }
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

    public function collectModules($id = '*', $application = '*')
    {
        $modules = $backend = $frontend = [];
        if ($application == '*') {
            if (self::isAdvanced()) {
                $backend = ArrayHelper::getValue(self::$configs['backend'], 'modules');
                $frontend = ArrayHelper::getValue(self::$configs['frontend'], 'modules');
                $modules = array_merge($backend, $frontend);
            } else {
                $modules = ArrayHelper::getValue(self::$configs['basic'], 'modules');
            }
        } else {
            foreach (self::$configs as $config) {
                if (Inflector::camelize(ArrayHelper::getValue($config, 'id')) == $application) {
                    $modules = ArrayHelper::getValue($config, 'modules', []);
                    break;
                }
            }
        }
        $result = [null];
        foreach ($modules as $name => $module) {
            if ($id == '*' || Inflector::camelize($name) == Inflector::camelize($id)) {
                $result[] = [$name => $module];
            }
        }
        return $result;
    }
}
