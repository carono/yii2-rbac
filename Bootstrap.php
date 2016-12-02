<?php
namespace carono\yii2rbac;

use yii\base\Application;
use yii\base\BootstrapInterface;
use yii\gii\Module;


/**
 * Class Bootstrap
 *
 * @package carono\yii2rbac
 */
class Bootstrap implements BootstrapInterface
{

	/**
	 * Bootstrap method to be called during application bootstrap stage.
	 *
	 * @param Application $app the application currently running
	 */
	public function bootstrap($app)
	{
        if ($app instanceof \yii\console\Application) {
            if (!isset($app->controllerMap['rbac'])) {
                $app->controllerMap['rbac'] = 'carono\yii2rbac\RbacController';
            }
        }
    }
}