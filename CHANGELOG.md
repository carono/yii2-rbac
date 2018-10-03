1.0.17
* Добавлена возможность указать данные для правил
```
'permissions' => [
    'Basic:Site:*' => ['user', 'data' => ['myparam' => 'Произвольные данные'], 'description'=>'Акшены сайта']
]

'permissionsByRole' => [
    'user' => ['Basic:Site:*' => ['data' => ['myparam' => 'Произвольные данные'], 'description'=>'Акшены сайта']
]
```

1.0.16
* \carono\yii2rbac\RoleManagerFilter добавлена возможность указать свой клас для проверки прав через $roleManagerClass