<?php

namespace carono\yii2rbac;

use yii\filters\AccessControl;

class RoleManagerFilter extends AccessControl
{
    public $roleManagerClass = '\carono\yii2rbac\RoleManager';

    public function init()
    {
        $rule = [
            'allow'         => true,
            'matchCallback' => function ($rule, $action) {
                return call_user_func([$this->roleManagerClass, 'checkAccess'], $action);
            },
        ];
        $this->rules[] = \Yii::createObject(array_merge($this->ruleConfig, $rule));
        parent::init();
    }
}
