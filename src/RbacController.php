<?php

namespace carono\yii2rbac;

use yii\base\InlineAction;
use yii\console\Controller;
use yii\helpers\ArrayHelper;
use yii\helpers\Console;
use yii\helpers\Inflector;
use yii\helpers\StringHelper;
use yii\rbac\Role;
use yii\rbac\Rule;

class RbacController extends Controller
{
    public $identityClass;
    public $roles = [];
    public $permissions = [];
    public $permissionsByRole = [];
    public $authManager = 'authManager';
    public $deny = [];
    public $cache = 'cache';
    public $rules = [];
    public $removeUnusedRoles = true;
    public $removeUnusedRules = true;
    public $overwritePermissionParams = false;

    public $defaultConfigs = [
        [
            '@app/config/web.php'
        ],
        [
            '@common/config/main.php',
            '@common/config/main-local.php',
            '@backend/config/main.php',
            '@backend/config/main-local.php'
        ],
        [
            '@common/config/main.php',
            '@common/config/main-local.php',
            '@frontend/config/main.php',
            '@frontend/config/main-local.php'
        ]
    ];
    public $configs = [];
    protected $role;
    protected $user;

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
        RoleManager::$authManager = $this->authManager;
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

    protected function getPermissions()
    {
        return array_merge($this->permissions, $this->permissions());
    }

    protected function getRoles()
    {
        return array_merge($this->roles, $this->roles());
    }

    protected function applyRoles()
    {
        $roles = $this->getRoles();
        if (!$roles && !$this->permissionsByRole) {
            Console::output('Roles not registered, nothing to do');
            exit;
        }
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
            Console::output("Create '$role' role");
        }
    }

    protected function applyPermissions()
    {
        $permissions = $this->getPermissions();
        if (!$permissions && !$this->permissionsByRole) {
            Console::output('Permissions not registered, nothing to do');
            exit;
        }
        foreach ($permissions as $permission => $roles1) {
            foreach ($this->normalizePermission($permission) as $name) {
                RoleManager::createPermission($name);
                foreach ($roles1 as $key => $role) {
                    if (is_array($role) && \in_array($key, ['data', 'description'])) {
                        $params[$key] = $role;
                        $permissionModel = RoleManager::getPermission($name);
                        RoleManager::updatePermissionParams($permissionModel, $params);
                        continue;
                    }
                    if (!RoleManager::getRole($role)) {
                        Console::output("FAIL add '$name' permission for '$role'. Role '$role' not found");
                        exit;
                    }
                    RoleManager::addChild($role, $name);
                    Console::output("Set '$name' for '$role'");
                }
            }
        }

        foreach ($this->permissionsByRole as $role => $permissions) {
            foreach ($permissions as $key => $permission) {
                $params = [];
                if (is_array($permission) && is_string($key)) {
                    $params = $permission;
                    $permission = $key;
                }
                if ($this->overwritePermissionParams) {
                    $params['data'] = ArrayHelper::getValue($params, 'data');
                    $params['description'] = ArrayHelper::getValue($params, 'description');
                }
                foreach ($this->normalizePermission($permission) as $name) {
                    RoleManager::createPermission($name, $params);
                    if ($params) {
                        $permissionModel = RoleManager::getPermission($name);
                        RoleManager::updatePermissionParams($permissionModel, $params);
                    }
                    if (!RoleManager::getRole($role)) {
                        Console::output("FAIL add '$name' permission for '$role'. Role '$role' not found");
                        exit;
                    }
                    RoleManager::addChild($role, $name);
                    Console::output("Set '$name' for '$role'");
                }
            }
        }
    }

    protected function applyDenyPermissions()
    {
        if (!$this->deny) {
            return Console::output('Deny permissions not registered, nothing to do');
        }
        foreach ($this->deny as $permission => $roles3) {
            foreach ($roles3 as $role) {
                RoleManager::auth()->removeChild(RoleManager::getRole($role), RoleManager::getPermission($permission));
                Console::output("Remove '$permission' for '$role'");
            }
        }
    }

    protected function removeUnusedRoles()
    {
        $roles = $this->getRoles();
        $diffRoles = array_diff(array_keys(RoleManager::auth()->getRoles()), array_keys($roles));
        if (!$diffRoles) {
            return Console::output('There are no roles to delete');
        }
        foreach ($diffRoles as $role) {
            RoleManager::removeRole($role);
            Console::output("Remove '$role' role");
        }
    }

    protected function removeUnusedRules()
    {
        /**
         * @var Rule $ruleClass
         */
        $ruleNames = [];
        foreach ($this->rules as $permission => $ruleClass) {
            $ruleNames[] = (new $ruleClass())->name;
        }
        $diffRules = array_diff(array_keys(RoleManager::auth()->getRules()), $ruleNames);
        if (!$diffRules) {
            Console::output("There are no rules to delete");
        }
        foreach ($diffRules as $rule) {
            RoleManager::auth()->remove(RoleManager::auth()->getRule($rule));
            Console::output("Remove rule '$rule'");
        }
    }

    public function actionIndex()
    {
        $transaction = \Yii::$app->db->beginTransaction();
        Console::output("Creating roles");
        $this->applyRoles();

        Console::output("\nCreating permissions");
        $this->applyPermissions();

        Console::output("\nApply deny permissions");
        $this->applyDenyPermissions();

        if ($this->removeUnusedRoles) {
            Console::output("\nRemove unused roles");
            $this->removeUnusedRoles();
        }

        Console::output("\nApply rules");
        $this->applyRules();

        if ($this->removeUnusedRules) {
            Console::output("\nRemove unused rules");
            $this->removeUnusedRules();
        }
        $transaction->commit();
        $this->flushCache();
    }

    protected function applyRules()
    {
        /**
         * @var Rule $ruleClass
         */
        if (!$this->rules) {
            Console::output("There are no rules for creating");
            return;
        }
        foreach ($this->rules as $permission => $ruleClassName) {
            foreach ($this->normalizePermission($permission) as $name) {
                $permissionModel = RoleManager::getPermission($name);
                if (!$permissionModel) {
                    Console::output("FAIL add rules. Permission '$name' not found");
                    exit;
                }
                $ruleClass = new $ruleClassName();
                if (empty($ruleClass->name)) {
                    Console::output("FAIL add rules. Permission '$name' not found");
                    exit;
                }
                if (!RoleManager::auth()->getRule($ruleClass->name)) {
                    RoleManager::auth()->add($ruleClass);
                }
                $permissionModel->ruleName = $ruleClass->name;
                RoleManager::auth()->update($name, $permissionModel);
                Console::output("Set rule '{$ruleClass->name}' for '$name'");
            }
        }
    }

    public function flushCache()
    {
        try {
            \Yii::$app->{$this->cache}->flush();
        } catch (\Exception $e) {
            echo "Fail clear cache: " . $e->getMessage();
        }
    }

    public function normalizePermission($expressionPermission)
    {
        if (strpos($expressionPermission, '*') !== false) {
            $app = RoleManager::getApplicationFromPermission($expressionPermission);
            $module = RoleManager::getModuleFromPermission($expressionPermission);
            $controller = RoleManager::getControllerFromPermission($expressionPermission);
            $action = RoleManager::getActionFromPermission($expressionPermission);

            $applications = $this->collectApplications($app);

            $permissions = [];
            if (!$applications) {
                Console::output('ERROR: Applications not found in expression: ' . $app);
                exit;
            }

            foreach ($applications as $application) {
                $modules = $this->collectModules($module, $application);
                $controllers = $this->collectRegularControllers($controller, $application);
                foreach ($modules as $moduleConfig) {
                    $controllers = array_merge(
                        $controllers, $this->collectControllers($controller, $moduleConfig, $applications)
                    );
                }
                $actions = $this->collectActions($controllers, $action);

                foreach ($actions as $action) {
                    RoleManager::$defaultApplicationId = $application;
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

    protected static function mergeConfigs($array)
    {
        $result = [];
        foreach ($array as $item) {
            try {
                $file = \Yii::getAlias($item);
                if (file_exists($file)) {
                    $result = ArrayHelper::merge($result, require $file);
                }
            } catch (\Exception $e) {
            }
        }
        return $result;
    }

    protected function getConfigs()
    {
        return $this->configs ?: $this->defaultConfigs;
    }

    public function collectRegularControllers($pattern, $applications = [])
    {
        $f = function ($v) {
            return [str_replace('Controller', '', basename($v, '.php')) => $v];
        };
        $f2 = function ($v) {
            return key($v);
        };
        $controllers = [];
        foreach ($this->getConfigs() as $configs) {
            $config = static::mergeConfigs($configs);
            if (in_array(Inflector::camelize(ArrayHelper::getValue($config, 'id')), (array)$applications)) {
                $p = str_replace('\\', '/', ArrayHelper::getValue($config, 'controllerNamespace', 'app\controllers'));
                $names = array_filter(array_map($f, glob(\Yii::getAlias("@{$p}/*Controller.php"))), $f2);
                foreach ($names as $elem) {
                    $name = key($elem);
                    $file = current($elem);
                    $className = self::extractClassByPath($file);
                    if (StringHelper::matchWildcard($pattern, Inflector::camelize($name))) {
                        $controllers[] = ['class' => $className, 'name' => $name, 'module' => null];
                    }
                }
            }
        }
        return $controllers;
    }

    public function collectControllers($pattern, $moduleConfig, $applications)
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
            if (StringHelper::matchWildcard($pattern, Inflector::camelize($name)) && $flag) {
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
        foreach ($this->getConfigs() as $config) {
            if (Inflector::camelize(ArrayHelper::getValue($config, 'id')) == Inflector::camelize($id)) {
                $modules = ArrayHelper::getValue($config, 'modules', []);
                break;
            }
        }
        return $modules;
    }

    public function collectModules($pattern = '*', $applications = [])
    {
        $items = [];
        foreach ((array)$applications as $app) {
            $items[$app] = array_merge($this->extractModulesById($app));
        }
        $result = [];
        foreach ($items as $app => $modules) {
            if (!in_array(Inflector::camelize($app), (array)$applications)) {
                continue;
            }
            foreach ($modules as $name => $item) {
                if (is_string($item)) {
                    $item = ['class' => $item];
                }
                if (StringHelper::matchWildcard($pattern, Inflector::camelize($name))) {
                    $result[] = [$name => $item + ['app' => $app]];
                }
            }
        }
        return $result;
    }

    public function collectApplications($pattern = '*')
    {
        $result = [];
        foreach ($this->getConfigs() as $configs) {
            if ($config = static::mergeConfigs($configs)) {
                $result[] = Inflector::camelize(ArrayHelper::getValue($config, 'id'));
            }
        }
        return array_filter($result, function ($item) use ($pattern) {
            return StringHelper::matchWildcard($pattern, $item);
        });
    }
}
