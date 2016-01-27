<?php
/*!
 * yii2 extension - 同盾风险决策系统接口
 * xiewulong <xiewulong@vip.qq.com>
 * https://github.com/diankego/yii2-fraudmetrix
 * https://raw.githubusercontent.com/diankego/yii2-fraudmetrix/master/LICENSE
 * create: 2016/1/26
 * update: 2016/1/27
 * version: 0.0.1
 */

namespace yii\fraudmetrix;

use yii\base\ErrorException;

class Manager {

	//网关
	private $api;

	//同盾分配的合作方标示
	public $partner_code;

	//同盾分配的API密钥
	public $secret_key;

	//debug
	public $dev = false;

	//返回结果数据
	public $result;

	//错误码
	public $errcode;

	//错误码说明
	public $errmsg;

	//CA根证书
	private $cacert = 'cacert.pem';

	/**
	 * 检测注册事件
	 * @method checkRegister
	 * @since 0.0.1
	 * @param {string} $account_login 登录账户名
	 * @param {string} $account_mobile 注册手机
	 * @param {string} [$account_email=null] 注册邮箱
	 * @param {string} [$id_number=null] 注册身份证
	 * @param {string} [$account_password=null] 注册密码摘要：建议先加密后再提供
	 * @param {string} [$rem_code=null] 注册邀请码
	 * @param {int} [$state=null] 状态校验结果
	 * @return {boolean}
	 * @example \Yii::$app->fraudmetrix->checkRegister($account_login, $account_mobile, $account_email, $id_number, $account_password, $rem_code, $state);
	 */
	public function checkRegister($account_login, $account_mobile, $account_email = null, $id_number = null, $account_password = null, $rem_code = null, $state = null) {
		return $this->getResult([
			'event_id' => 'register_professional_web',
			'ip_address' => $this->getUserIp(),
			'account_login' => $account_login,
			'account_mobile' => $account_mobile,
			'account_email' => $account_email,
			'id_number' => $id_number,
			'account_password' => $account_password,
			'rem_code' => $rem_code,
			'state' => $state,
		]);
	}

	/**
	 * 检测登录事件
	 * @method checkLogin
	 * @since 0.0.1
	 * @param {string} $account_login 登录账户名
	 * @param {int} $state 状态校验结果（密码校验结果：0表示密码正确，1表示密码错误）
	 * @param {string} [$account_password=null] 登录密码摘要：建议先加密后再提供
	 * @return {boolean}
	 * @example \Yii::$app->fraudmetrix->checkLogin($account_login, $state, $account_password);
	 */
	public function checkLogin($account_login, $state = null, $account_password = null) {
		return $this->getResult([
			'event_id' => 'login_professional_web',
			'ip_address' => $this->getUserIp(),
			'account_login' => $account_login,
			'state' => $state,
			'account_password' => $account_password,
		]);
	}

	/**
	 * 检测短信事件
	 * @method checkSms
	 * @since 0.0.1
	 * @param {string} $account_mobile 申请验证码手机号
	 * @param {string} [$sms_content=null] 短信内容
	 * @param {int} [$state=null] 状态校验结果
	 * @return {boolean}
	 * @example \Yii::$app->fraudmetrix->checkSms($account_mobile, $sms_content, $state);
	 */
	public function checkSms($account_mobile, $sms_content = null, $state = null) {
		return $this->getResult([
			'event_id' => 'sms_professional_web',
			'ip_address' => $this->getUserIp(),
			'account_mobile' => $account_mobile,
			'sms_content' => $sms_content,
			'state' => $state,
		]);
	}

	/**
	 * 获取结果
	 * @method getResult
	 * @since 0.0.1
	 * @param {array} $params 参数
	 * @return {boolean}
	 */
	private function getResult($params) {
		$this->result = json_decode($this->curl($this->getApi(), http_build_query(array_merge(['partner_code' => $this->partner_code, 'secret_key' => $this->secret_key], $params))));

		if(!$this->result){
			return false;
		}

		if(!$this->result->success){
			$reason_code = explode(':', $this->result->reason_code);
			$this->errcode = $reason_code[0];
			$this->errmsg = $reason_code[1];
			return false;
		}

		return true;
	}

	/**
	 * 获取用户端访问ip
	 * @method getUserIp
	 * @since 0.0.1
	 * @return {string}
	 */
	private function getUserIp() {
		return \Yii::$app->request->userIp;
	}

	/**
	 * 获取网关
	 * @method getApi
	 * @since 0.0.1
	 * @return {string}
	 */
	private function getApi() {
		if(!$this->api){
			$this->api = 'https://api' . ($this->dev ? 'test' : '') . '.fraudmetrix.cn/riskService';
		}

		return $this->api;
	}

	/**
	 * curl远程获取数据方法
	 * @method curl
	 * @since 0.0.1
	 * @param {string} $url 请求地址
	 * @param {array|string} [$data=null] post数据
	 * @param {string} [$useragent=null] 模拟浏览器用户代理信息
	 * @return {string}
	 */
	private function curl($url, $data = null, $useragent = null) {
		$curl = curl_init();
		curl_setopt($curl, CURLOPT_URL, $url);
		curl_setopt($curl, CURLOPT_HEADER, 0);
		curl_setopt($curl, CURLOPT_RETURNTRANSFER, 1);
		curl_setopt($curl, CURLOPT_SSL_VERIFYPEER, 1);
		curl_setopt($curl, CURLOPT_SSL_VERIFYHOST, 2);
		curl_setopt($curl, CURLOPT_CAINFO, __DIR__ . DIRECTORY_SEPARATOR . $this->cacert);
		curl_setopt($curl, CURLOPT_TIMEOUT_MS, 500);

		if(!empty($data)) {
			curl_setopt($curl, CURLOPT_POST, 1);
			curl_setopt($curl, CURLOPT_POSTFIELDS, $data);
		}
		if(!empty($useragent)) {
			curl_setopt($curl, CURLOPT_USERAGENT, $useragent);
		}

		$data = curl_exec($curl);
		curl_close($curl);

		echo $data;

		return $data;
	}

}
