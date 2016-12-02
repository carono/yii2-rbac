<?php

namespace carono\yii2rbac;

use yii\base\InlineAction;
use yii\console\Controller;
use yii\helpers\ArrayHelper;
use yii\helpers\Console;
use yii\helpers\StringHelper;

class RbacController extends Controller
{
    public $userClass = 'app\models\User';
    public $roles = [];
    public $permissions = [];
    public $basicId;
    public $frontendId;
    public $backendId;
    protected static $configs = [];

    public function init()
    {
        RoleManager::$userClass = $this->userClass;
        if (self::isAdvanced()) {
            if (!$this->backendId) {
                $this->backendId = ArrayHelper::getValue(self::getBackendConfig(), 'id');
            }
            if (!$this->frontendId) {
                $this->frontendId = ArrayHelper::getValue(self::getFrontendConfig(), 'id');
            }
        } else {
            if (!$this->basicId) {
                $this->basicId = ArrayHelper::getValue(self::getBasicConfig(), 'id');
            }
        }
        parent::init();
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
                    echo "Set $name for $role\n";
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
            $arr = explode(':', $expressionPermission);
            $modules = $this->collectModules($arr[0]);
            $controllers = $this->collectControllers($modules, $arr[1]);
            $actions = $this->collectActions($controllers, $arr[2]);
            $permissions = [];
            foreach ($actions as $action) {
                $appId = $this->getApplicationIdByControllerClass($action->controller);
                if (RoleManager::$defaultApplicationId = $appId) {
                    $permissions[] = RoleManager::formPermissionByAction($action);
                } else {
//                    var_dump(get_class($action->controller));
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
//                    var_dump($controller);
//                    exit;

                    foreach ($controller->actions() as $name => $value) {
                        $actions[] = new InlineAction($name, $controller, $value);
                    }
                }
            } elseif (method_exists($controller, $method = 'action' . $id)) {
                $actions[] = new InlineAction($id, $controller, $method);
            }
            unset($controller);
            gc_collect_cycles();
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
        $controllers = [];
        $moduleModel = null;
        foreach ($modules as $module) {
            if ($id == "*") {
                $f = function ($v) {
                    return [str_replace('Controller', '', basename($v, '.php')) => $v];
                };
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
            } else {
                var_dump('1111');
                exit;
                $names = [$id];
            }
            foreach (array_filter($names) as $elem) {
                $name = key($elem);
                $file = current($elem);
                $className = self::extractClassByPath($file);
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

    public function collectModules($id = '*')
    {
        $modules = [];
        if ($id == '*') {
            if (self::isAdvanced()) {
                $backend = ArrayHelper::getValue(self::$configs['backend'], 'modules');
                $frontend = ArrayHelper::getValue(self::$configs['frontend'], 'modules');
                $modules = array_merge($backend, $frontend);
            } else {
                $modules = ArrayHelper::getValue(self::$configs['basic'], 'modules');
            }
        }
        $result = [null];
        foreach ($modules as $name => $module) {
            $result[] = [$name => $module];
        }
        return $result;
    }
}
