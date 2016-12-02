<?php

namespace carono\yii2rbac;

use yii\base\InlineAction;
use yii\console\Controller;
use yii\helpers\Console;

class RbacController extends Controller
{
    public $userClass = 'app\models\User';
    public $roles = [];
    public $permissions = [];
    public $applicationId;

    public function init()
    {
        RoleManager::$userClass = $this->userClass;
        RoleManager::$defaultApplicationId = $this->applicationId;
        if (!$this->applicationId) {
            Console::output('Attribute "applicationId" is required');
            exit;
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

    public function normalizePermission($expressionPermission)
    {
        if (strpos($expressionPermission, '*') !== false) {
            $arr = explode(':', $expressionPermission);
            $modules = $this->collectModules($arr[0]);
            $controllers = $this->collectControllers($modules, $arr[1]);
            $actions = $this->collectActions($controllers, $arr[2]);
            $permissions = [];
            foreach ($actions as $action) {
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

    public function collectControllers($modules, $id)
    {
        $controllers = [];
        foreach ($modules as $module) {
            if ($id == "*") {
                $f = function ($v) {
                    return str_replace('Controller', '', basename($v, '.php'));
                };
                if ($module) {
                    $names = array_map(
                        $f, glob(\Yii::getAlias("@app/modules/{$module->id}/controllers/*Controller.php"))
                    );
                } else {
                    $names = array_map($f, glob(\Yii::getAlias('@app/controllers/*Controller.php')));
                }
            } else {
                $names = [$id];
            }
            foreach (array_filter($names) as $name) {
                if ($module) {
                    $className = join('\\', ['app', 'modules', $module->id, 'controllers', $name . "Controller"]);
                } else {
                    $className = join('\\', ['app', 'controllers', $name . "Controller"]);
                }
                if (class_exists($className)) {
                    $controllers[] = new $className($name, $module);
                }
            }
        }
        return $controllers;
    }

    public function collectModules($id = '*')
    {
        $f = function ($v) {
            $name = basename($v);
            $file = basename(current(glob($v . DIRECTORY_SEPARATOR . '*.php')), '.php');
            if (class_exists($className = join('\\', ['app', 'modules', $name, $file]))) {
                return new $className($name, null);
            } else {
                return null;
            }
        };
        $dir = [\Yii::getAlias("@app"), "modules", "*"];
        $modules = array_filter(array_map($f, glob(join(DIRECTORY_SEPARATOR, $dir))));
        if ($id == '*') {
            return array_merge($modules, [null]);
        } else {
            foreach ($modules as $module) {
                if ($module->id == strtolower($id)) {
                    return [$module];
                }
            }
            return [null];
        }
    }
}
