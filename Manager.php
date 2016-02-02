<?php
/*!
 * yii2 extension - 同盾风险决策系统接口
 * xiewulong <xiewulong@vip.qq.com>
 * https://github.com/diankego/yii2-fraudmetrix
 * https://raw.githubusercontent.com/diankego/yii2-fraudmetrix/master/LICENSE
 * create: 2016/1/26
 * update: 2016/2/2
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
	 * 注册事件检测
	 * @method checkRegister
	 * @since 0.0.1
	 * @param {string} $account_login 登录账户名
	 * @param {string} $account_mobile 注册手机
	 * @param {array} [$options=[]] 可选参数
	 * @param {string} [$options[account_email]] 注册邮箱
	 * @param {string} [$options[id_number]] 注册身份证
	 * @param {string} [$options[account_password]] 注册密码摘要：建议先加密后再提供
	 * @param {string} [$options[rem_code]] 注册邀请码
	 * @param {int} [$options[state]] 状态校验结果
	 * @param {string} [$options[token_id]] TokenId, 设备ID
	 * @return {boolean}
	 * @example \Yii::$app->fraudmetrix->checkRegister($account_login, $account_mobile, $options);
	 */
	public function checkRegister($account_login, $account_mobile, $options = []) {
		$params = array_merge([
			'event_id' => 'register_professional_web',
			'ip_address' => $this->getUserIp(),
			'account_login' => $account_login,
			'account_mobile' => $account_mobile,
		], $options);

		return $this->getResult($params);
	}

	/**
	 * 登录事件检测
	 * @method checkLogin
	 * @since 0.0.1
	 * @param {string} $account_login 登录账户名
	 * @param {array} [$options=[]] 可选参数
	 * @param {string} [$options[token_id]] TokenId, 设备ID
	 * @param {string} [$options[account_password]] 登录密码摘要：建议先加密后再提供
	 * @param {int} [$options[state]] 状态校验结果
	 * @return {boolean}
	 * @example \Yii::$app->fraudmetrix->checkLogin($account_login, $options);
	 */
	public function checkLogin($account_login, $options = []) {
		$params = array_merge([
			'event_id' => 'login_professional_web',
			'ip_address' => $this->getUserIp(),
			'account_login' => $account_login,
		], $options);

		return $this->getResult($params);
	}

	/**
	 * 短信事件检测
	 * @method checkSms
	 * @since 0.0.1
	 * @param {string} $account_mobile 申请验证码手机号
	 * @param {array} [$options=[]] 可选参数
	 * @param {string} [$options[sms_content]] 短信内容
	 * @param {int} [$options[state]] 状态校验结果
	 * @param {string} [$options[token_id]] TokenId, 设备ID
	 * @return {boolean}
	 * @example \Yii::$app->fraudmetrix->checkSms($account_mobile, $options);
	 */
	public function checkSms($account_mobile, $options = []) {
		$params = array_merge([
			'event_id' => 'sms_professional_web',
			'ip_address' => $this->getUserIp(),
			'account_mobile' => $account_mobile,
		], $options);

		return $this->getResult($params);
	}

	/**
	 * 借款事件检测
	 * @method checkLoan
	 * @since 0.0.1
	 * @param {string} $account_name 借款人姓名
	 * @param {string} $id_number 借款人身份证
	 * @param {string} $account_email 借款人邮箱
	 * @param {string} $account_mobile 借款人手机
	 * @param {array} [$options=[]] 可选参数
	 * @param {boolean} [$options[ip_address]=false] 是否提交用户侧IP地址或借款人IP地址
	 * @param {string} [$options[account_login]] 借款人账号(登录信贷理财平台的账户名)
	 * @param {string} [$options[account_phone]] 借款人座机(示例如057126307516)
	 * @param {string} [$options[qq_number]] 借款人QQ
	 * @param {string} [$options[organization]] 借款人工作单位
	 * @param {string} [$options[account_address]] 借款人地址
	 * @param {string} [$options[loan_purpose]] 借款用途
	 * @param {string} [$options[pay_amount]] 借贷金额(单位:元)
	 * @param {string} [$options[pay_currency]] 货币名称
	 * @param {string} [$options[card_number]] 借款人卡号
	 * @param {string} [$options[cc_bin]] 卡BIN
	 * @param {string} [$options[card_name]] 开户行名称
	 * @param {string} [$options[card_city]] 开户行所在省市
	 * @param {string} [$options[contacts_phone]] 联系人手机
	 * @param {string} [$options[contacts_id_number]] 联系人身份证
	 * @param {string} [$options[contacts_address]] 联系人地址
	 * @param {string} [$options[state]] 状态校验结果
	 * @param {string} [$options[token_id]] TokenId, 设备ID
	 * @return {boolean}
	 * @example \Yii::$app->fraudmetrix->checkLoan($account_name, $id_number, $account_email, $account_mobile, $options);
	 */
	public function checkLoan($account_name, $id_number, $account_email, $account_mobile, $options = []) {
		$params = array_merge([
			'event_id' => 'loan_professional_web',
			'account_name' => $account_name,
			'id_number' => $id_number,
			'account_email' => $account_email,
			'account_mobile' => $account_mobile,
		], $options);

		if(isset($params['ip_address']) && $params['ip_address']){
			$params['ip_address'] = $this->getUserIp();
		}

		return $this->getResult($params);
	}

	/**
	 * 营销事件检测
	 * @method checkMarketing
	 * @since 0.0.1
	 * @param {string} $account_login 账户名
	 * @param {string} $account_mobile 账户手机
	 * @param {array} [$options=[]] 可选参数
	 * @param {string} [$options[id_number]] 账户身份证
	 * @param {string} [$options[account_email]] 账户邮箱
	 * @param {string} [$options[item_count]] 商品数量
	 * @param {array} [$options[items]] 商品列表
	 * @param {int} [$options[state]] 营销结果
	 * @param {string} [$options[token_id]] TokenId, 设备ID
	 * @return {boolean}
	 * @example \Yii::$app->fraudmetrix->checkMarketing($account_login, $account_mobile, $options);
	 */
	public function checkMarketing($account_login, $account_mobile, $options = []) {
		$params = array_merge([
			'event_id' => 'marketing_professional_web',
			'ip_address' => $this->getUserIp(),
			'account_login' => $account_login,
			'account_mobile' => $account_mobile,
		], $options);

		return $this->getResult($params);
	}

	/**
	 * 交易事件检测
	 * @method checkTrade
	 * @since 0.0.1
	 * @param {string} $account_login 买家账户
	 * @param {string} $account_mobile 买家手机
	 * @param {int} $pay_amount 交易金额(单位:元)
	 * @param {string} $pay_currency 货币名称
	 * @param {int} $items_count 商品数量
	 * @param {array} $items 商品列表
	 * @param {string} $payee_userid 卖家账户
	 * @param {string} $payee_name 卖家姓名
	 * @param {string} $payee_id_number 卖家身份证
	 * @param {string} $payee_mobile 卖家手机
	 * @param {string} $deliver_mobile 收货人手机
	 * @param {string} $deliver_address_street 收货人街道地址
	 * @param {string} $deliver_address_county 收货人街区地址
	 * @param {string} $deliver_address_city 收货人城市地址
	 * @param {string} $deliver_address_province 收货人省份地址
	 * @param {array} [$options=[]] 可选参数
	 * @param {string} [$options[account_name]] 买家姓名
	 * @param {string} [$options[id_number]] 买家身份证
	 * @param {string} [$options[account_email]] 买家邮箱
	 * @param {string} [$options[card_number]] 买家卡号
	 * @param {string} [$options[pay_method]] 买家支付方式
	 * @param {string} [$options[pay_account]] 买家支付账号
	 * @param {string} [$options[transaction_id]] 交易订单
	 * @param {string} [$options[payee_email]] 卖家邮箱
	 * @param {string} [$options[payee_card_number]] 卖家卡号
	 * @param {string} [$options[deliver_name]] 收货人姓名
	 * @param {string} [$options[deliver_phone]] 收货人座机(示例如057126307516)
	 * @param {string} [$options[deliver_address_country]] 收货人国家地址
	 * @param {string} [$options[deliver_zip_code]] 收货人邮编
	 * @param {string} [$options[account_address_province]] 买家省份地址
	 * @param {string} [$options[account_address_city]] 买家城市地址
	 * @param {string} [$options[account_address_county]] 买家县区地址
	 * @param {string} [$options[account_address_street]] 买家街道地址
	 * @param {string} [$options[account_address_country]] 买家国家地址
	 * @param {string} [$options[account_zip_code]] 买家邮编
	 * @param {string} [$options[state]] 状态校验结果
	 * @param {string} [$options[token_id]] TokenId, 设备ID
	 * @return {boolean}
	 * @example \Yii::$app->fraudmetrix->checkTrade($account_login, $account_mobile, $pay_amount, $pay_currency, $items_count, $items, $payee_userid, $payee_name, $payee_id_number, $payee_mobile, $deliver_mobile, $deliver_address_street, $deliver_address_county, $deliver_address_city, $deliver_address_province, $options);
	 */
	public function checkTrade($account_login, $account_mobile, $pay_amount, $pay_currency, $items_count, $items, $payee_userid, $payee_name, $payee_id_number, $payee_mobile, $deliver_mobile, $deliver_address_street, $deliver_address_county, $deliver_address_city, $deliver_address_province, $options = []) {
		$params = array_merge([
			'event_id' => 'trade_professional_web',
			'ip_address' => $this->getUserIp(),
			'account_login' => $account_login,
			'account_mobile' => $account_mobile,
			'pay_amount' => $pay_amount,
			'pay_currency' => $pay_currency,
			'items_count' => $items_count,
			'items' => $items,
			'payee_userid' => $payee_userid,
			'payee_name' => $payee_name,
			'payee_id_number' => $payee_id_number,
			'payee_mobile' => $payee_mobile,
			'deliver_mobile' => $deliver_mobile,
			'deliver_address_street' => $deliver_address_street,
			'deliver_address_county' => $deliver_address_county,
			'deliver_address_city' => $deliver_address_city,
			'deliver_address_province' => $deliver_address_province,
		], $options);

		return $this->getResult($params);
	}

	/**
	 * 支付事件检测
	 * @method checkPayment
	 * @since 0.0.1
	 * @param {string} $account_login 付款人账户
	 * @param {string} $account_mobile 付款人手机
	 * @param {string} $pay_method 支付方式
	 * @param {string} $pay_amount 支付金额(单位:元)
	 * @param {string} $pay_currency 货币名称
	 * @param {array} [$options=[]] 可选参数, 有以下字段
	 * @param {string} [$options[account_name]] 付款人姓名
	 * @param {string} [$options[id_number]] 付款人身份证
	 * @param {string} [$options[account_email]] 付款人邮箱
	 * @param {string} [$options[account_phone]] 付款人座机(示例如057126307516)
	 * @param {string} [$options[card_number]] 付款人卡号
	 * @param {string} [$options[cc_bin]] 卡BIN
	 * @param {string} [$options[pay_id]] 支付流水
	 * @param {string} [$options[payee_userid]] 收款人账户
	 * @param {string} [$options[payee_name]] 收款人姓名
	 * @param {string} [$options[payee_email]] 收款人邮箱
	 * @param {string} [$options[payee_mobile]] 收款人手机
	 * @param {string} [$options[payee_phone]] 收款人座机(示例如057126307516)
	 * @param {string} [$options[payee_id_number]] 收款人身份证
	 * @param {string} [$options[payee_card_number]] 收款人卡号
	 * @param {string} [$options[card_accp_term_id]] 受卡机终端标识码:POS机码
	 * @param {string} [$options[card_binding_mobile]] 银行卡手机
	 * @param {string} [$options[state]] 状态校验结果
	 * @param {string} [$options[token_id]] TokenId, 设备ID
	 * @return {boolean}
	 * @example \Yii::$app->fraudmetrix->checkPayment($account_login, $account_mobile, $pay_method, $pay_amount, $pay_currency, $options);
	 */
	public function checkPayment($account_login, $account_mobile, $pay_method, $pay_amount, $pay_currency, $options = []) {
		$params = array_merge([
			'event_id' => 'payment_professional_web',
			'ip_address' => $this->getUserIp(),
			'account_login' => $account_login,
			'account_mobile' => $account_mobile,
			'pay_method' => $pay_method,
			'pay_amount' => $pay_amount,
			'pay_currency' => $pay_currency,
		], $options);

		return $this->getResult($params);
	}

	/**
	 * 绑卡事件检测
	 * @method checkBinding
	 * @since 0.0.1
	 * @param {string} $account_login 账户名(登录信贷理财平台的账户名)
	 * @param {string} $account_name 账户姓名(绑卡四要素)
	 * @param {string} $id_number 账户身份证(绑卡四要素)
	 * @param {string} $card_number 银行卡号(绑卡四要素)
	 * @param {string} $card_binding_mobile 银行卡手机(绑卡四要素)
	 * @param {array} [$options=[]] 可选参数
	 * @param {string} [$options[account_mobile]] 账户手机
	 * @param {string} [$options[cc_bin]] 卡BIN
	 * @param {int} [$options[state]] 状态校验结果
	 * @param {string} [$options[token_id]] TokenId, 设备ID
	 * @return {boolean}
	 * @example \Yii::$app->fraudmetrix->checkBinding($account_login, $account_name, $id_number, $card_number, $card_binding_mobile, $options);
	 */
	public function checkBinding($account_login, $account_name, $id_number, $card_number, $card_binding_mobile, $options = []) {
		$params = array_merge([
			'event_id' => 'binding_professional_web',
			'ip_address' => $this->getUserIp(),
			'account_login' => $account_login,
			'account_name' => $account_name,
			'id_number' => $id_number,
			'card_number' => $card_number,
			'card_binding_mobile' => $card_binding_mobile,
		], $options);

		return $this->getResult($params);
	}

	/**
	 * 修改事件检测
	 * @method checkModify
	 * @since 0.0.1
	 * @param {string} $account_login 账户名(登录信贷理财平台的账户名)
	 * @param {string} $account_mobile 修改手机
	 * @param {string} $card_number 修改银行卡号
	 * @param {array} [$options=[]] 可选参数
	 * @param {string} [$options[account_email]] 修改邮箱
	 * @param {int} [$options[state]] 状态校验结果
	 * @param {string} [$options[token_id]] TokenId, 设备ID
	 * @return {boolean}
	 * @example \Yii::$app->fraudmetrix->checkModify($account_login, $account_mobile, $card_number, $options);
	 */
	public function checkModify($account_login, $account_mobile, $card_number, $options = []) {
		$params = array_merge([
			'event_id' => 'modify_professional_web',
			'ip_address' => $this->getUserIp(),
			'account_login' => $account_login,
			'account_mobile' => $account_mobile,
			'card_number' => $card_number,
		], $options);

		return $this->getResult($params);
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

		if(!$this->result) {
			$this->errcode = '503';
			$this->errmsg = '接口服务不可用';
			return false;
		}

		if(!$this->result->success) {
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
		if(!$this->api) {
			$this->api = 'https://api' . ($this->dev ? 'test' : '') . '.fraudmetrix.cn/riskService';
		}

		return $this->api;
	}

	/**
	 * curl远程获取数据方法
	 * @method curl
	 * @since 0.0.1
	 * @param {string} $url 请求地址
	 * @param {array|string} [$data] post数据
	 * @param {string} [$useragent] 模拟浏览器用户代理信息
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

		if(!empty($data)) {
			curl_setopt($curl, CURLOPT_POST, 1);
			curl_setopt($curl, CURLOPT_POSTFIELDS, $data);
		}
		if(!empty($useragent)) {
			curl_setopt($curl, CURLOPT_USERAGENT, $useragent);
		}

		$data = curl_exec($curl);
		curl_close($curl);

		return $data;
	}

}
