<?php
namespace carono\yii2rbac;

use yii\behaviors\AttributeBehavior;
use yii\db\BaseActiveRecord;
use yii\helpers\ArrayHelper;

class AuthorBehavior extends AttributeBehavior
{
	public $attributes;
	public $asRobot = true;
	public $robot = null;
	public $createdAtAttribute = 'creator_id';
	public $updatedAtAttribute = 'updater_id';

	public function init()
	{
		parent::init();

		if (empty($this->attributes)) {
			$this->attributes = [
				BaseActiveRecord::EVENT_BEFORE_INSERT => [$this->createdAtAttribute, $this->updatedAtAttribute],
				BaseActiveRecord::EVENT_BEFORE_UPDATE => $this->updatedAtAttribute,
			];
		}
	}

	/**
	 * @inheritdoc
	 */
	protected function getValue($event)
	{
		if ($event->name == BaseActiveRecord::EVENT_BEFORE_INSERT) {
			$attr = ArrayHelper::getValue(
				$this->attributes, BaseActiveRecord::EVENT_BEFORE_INSERT, $this->createdAtAttribute
			);
			if (is_array($attr)) {
				$attr = current($attr);
			}
			if ($value = $event->sender->{$attr}) {
				return $value;
			}
		}
		return CurrentUser::getId($this->asRobot, $this->robot);
	}
}