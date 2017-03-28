# yii2-rbac

Очередная реализация RBAC для yii2. 

ВВЕДЕНИЕ
--------
Этот компонент помогает распределить доступы по конкретным action в контроллерах по ролям, в конфигах прописываются доступы,
выполняется команда для сброса прав, и база наполнена всеми указанными ролями, контроллерами и акшенами. Можно не прописывать каждый
action в конкретном контроллере, а указать '*' и команда соберёт все возможные.

УСТАНОВКА
---------
`composer require carono/yii2-rbac`

Не забудьте провести миграцию для таблиц
 
`yii migrate --migrationPath=@yii/rbac/migrations`

НАСТРОЙКА
---------
В `config/console.php` для basic редакции и в `console/main.php` для advanced, прописываем
```
'components' => [ 
       'authManager' => [ 
            // Настраиваем менеджер, чтобы можно было в консоли работать с правами
            'class'        => 'yii\rbac\DbManager',
            'defaultRoles' => ['guest', 'user'],
        ],
],        
'controllerMap' => [
        'rbac' => [
            'class'       => 'carono\yii2rbac\RbacController',
            'roles'       => [
                'guest'    => null,
                'user'     => null,
                'manager'  => 'user',
                'director' => 'manager', // Наследование директора от менеджера
                'root'     => null
            ],
            'permissions' => [
                '*:*:*'                => ['root'], // Для рута доступны все контроллеры
                'Basic:Site:*'         => ['guest'], // Для гостя разрешены все actions у SiteController
                'Basic:Director:*'     => ['director'],
                'updater_perm'         => ['dirctor'], // Простые доступы тоже можно создавать как обычно
                'Basic:Manager:*'      => ['manager'], // Будет доступно и директору, т.к. наследуется
                'Basic:Director:Index' => ['manager'], // Только один action у DirectorController
                'Ajax:*:*'             => ['user'] // Модуль Ajax, все контроллеры разрешаем авторизованным
            ]
        ],
    ]
```

После настройки, необходимо выполнить `yii rbac` чтобы создались роли и создались доступы по контроллерам.
Если настройки в конфиге изменились, то необходимо каждый раз вызывать команду. Все роли и доступы пересоздаются заново.
При этом, уже навешанные на пользователей роли не удаляются.

В базе создаются доступы вида `Module:Controller:Action`, если в настройках указывается '*' в любой части, то собираются
все модули, контроллеры или акшены. 


ОСОБЕННОСТИ
-----------

Все контроллеры без модулей, всё же имеют модуль, которым является Yii::$app, поэтому SiteController->actionIndex формирует
доступ как `Basic:Site:Index`, если в конфиге (web.php) изменить id вашего приложения с basic на my-app, то нужно и в настройках
контроллера указывать соответственно:  `MyApp:Site:Index`

КАК ПРИМЕНЯТЬ
-------------
В behaviors контроллера, можно использовать фильтр, который идет в комплекте
```
  public function behaviors()
    {
        return [
            'access' => [
                'class' => RoleManagerFilter::className(),
            ]
        ];
    }
```
или проверить самостоятельно
```
public function behaviors()
    {
        return [
            'access' => [
                'class' => AccessControl::className(),
                'rules' => [
                    [
                        'allow'         => true,
                        'matchCallback' => function ($rule, $action) {
                            return RoleManager::checkAccess($action);
                        }
                    ],
                ],
            ],
        ];
    }
```

ХЕЛПЕРЫ
-------
* RoleManager::formPermissionByAction(Yii::$app->controller->action) = Basic:Site:index
* RoleManager::checkAccessByUrl('/site/index?page=1', $user) = true, передаем ссылки или массив, как для Url::to
* RoleManager::checkAccess('Basic:Site:Index', $user), так же принимает и класс Action 

$user - класс прописанный у вас в конфигах - Yii::$app->user->identityClass, так же может быть primaryKey модели или username

РАБОТА С ADVANCED РЕДАКЦИЕЙ
---------------------------
Не сильно отличается от basic, только доступ может состоять как из 3х так и из 4х секций, Application:Module:Controller:Action

```
'controllerMap' => [
        'rbac' => [
            'class'       => 'carono\yii2rbac\RbacController',
            'roles'       => [
                'guest'    => null,
                'user'     => null,
                'manager'  => 'user',
                'director' => 'manager',
                'root'     => null
            ],
            'permissions' => [
                '*:*:*'                 => ['root'], // Для рута доступны все контроллеры как во frontend так и в backend
                'AppFrontend:Site:*'    => ['guest'], // Для гостя разрешены все actions у SiteController во frontend
                'AppBackend:Director:*' => ['director'],
                'AppFrontend:Ajax:*:*'  => ['user'] // Модуль Ajax, все контроллеры разрешаем во frontend
                '*:Site:Index'          => ['guest'] // Разрешаем SiteController->index как во frontend так и backend
            ]
        ],
    ]
```

ИЗВЕСТНЫЕ ПРОБЛЕМЫ
------------------
* Команда при сборе модулей и контроллеров создаёт их как объекты, поэтому может возникать ошибка, что класс уже используется
`Cannot use yii\web\Controller because the name is already in use` или любой другой класс, т.к. выгрузить загруженных класс нельзя
без дополнительных средств, придется добавлять в секцию с подключаемыми неймспейсами алиас `use yii\web\Controller as MyController` и т.д. обходного пути я пока не нашел.
