<?php
namespace app\index\controller;

use app\index\controller\ApiBase;
use think\Request;
use wxlogin\wxBizDataCrypt;
use think\Session;
use think\Cache;
use app\index\model\User;
use app\index\model\EncryptText;
use app\index\model\BaseTime;

class Index extends ApiBase
{
	private $uri = 'https://api.weixin.qq.com/sns/jscode2session';
	private $appid = 'wx27c5518144f3d1b1';
	private $secret = 'd58e8b92e4e7e7d34ec0f648cfa7d3b3';
	private $grant_type ='authorization_code';
	//默认key
	private $key ='shuaibi';

	//加密
	public function encrypt(Request $request){
		$content = $request->param('content');
		$session3rd = $request->param('session3rd');
		$openid = Cache::get($session3rd);

		$end_msg = parent::lock_url($content,$this->key);
		if($session3rd){
			//获取用户信息
			$user = new User();
			$userMsg = $user->where('openid',$openid)->find()->toArray();

			//保存到加解密的表
			//现在sign暂时还是写死的
			$encryptText = new EncryptText();
			$encryptText->data([
				'base_text'=>$content,
				'end_text'=>$end_msg,
				'type'=>1,
				'sign'=>'',
				'user_id'=>$userMsg['id']
			]);
			$encryptText->save();
		}
		return ['base_msg'=>$content,'encode_msg'=>$end_msg];
	}

	//历史记录
	public function lstHistory(Request $request)
	{
		$session3rd = $request->param('session3rd');
		$openid = Cache::get($session3rd);
		//获取用户信息
		$user = new User();
		$userMsg = $user->where('openid',$openid)->find()->toArray();

		//获取现在的时间
		$now = date('Y-m-d H:i:s');
		//七天前
		$seven_ago = date('Y-m-d',strtotime('-7 days'));

		//获取所有的historylist
		$encryptText = new EncryptText();
		$historyList = $encryptText->field("id,base_text,end_text,type,date_format(create_time,'%Y-%m-%d %H:%i:%s') as time")->where("create_time",'<',$now)->where("create_time",'>',$seven_ago)->where('user_id',$userMsg['id'])->order('id','desc')->select();
	
		return $historyList;
	}

	//解密
	public function decrypt(Request $request){
		$content = $request->param('content');
		$session3rd = $request->param('session3rd');
		$openid = Cache::get($session3rd);

		$end_msg = parent::unlock_url($content,$this->key);
		if($session3rd){
			//获取用户信息
			$user = new User();
			$userMsg = $user->where('openid',$openid)->find()->toArray();

			//保存到加解密的表
			//现在sign暂时还是写死的
			$encryptText = new EncryptText();
			$encryptText->data([
				'base_text'=>$content,
				'end_text'=>$end_msg,
				'type'=>2,
				'sign'=>'',
				'user_id'=>$userMsg['id']
			]);
			$encryptText->save();
		}
		return ['base_msg'=>$content,'encode_msg'=>$end_msg];
	}

	//清除历史
	public function del_history(Request $request){
		$id = $request->param('id');
		$session3rd = $request->param('session3rd');
		$openid = Cache::get($session3rd);

		$user = new User();
		$userMsg = $user->where('openid',$openid)->find()->toArray();

		//删除历史
		$encryptText = new EncryptText();
		$del_id = $encryptText->where('id',$id)->delete();
		$del_id?$return_msg = ['code'=>1,'msg'=>"删除成功"]:$return_msg = ['code'=>-1,'msg'=>"删除失败"];
		return $return_msg;
	}

	//登陆
	public function index(Request $request)
	{    	
		$code = $request->param('code');
		$rawData = $request->param('rawData');
		$signature  = $request->param('signature');
		$encryptedData  = $request->param('encryptedData');
		$iv  = $request->param('iv');
    	//开始

		$params = [
			'appid'=>$this->appid,
			'secret'=>$this->secret,
			'js_code'=>$code,
			'grant_type'=>$this->grant_type
		];

		$res = self::makeRequest($this->uri,$params);

		if($res['code']!=200||!isset($res['result'])){
			return self::ret_message('requestTokenFailed');
		}

		$reqData =json_decode($res['result'],true);
		if(!isset($reqData['session_key'])){
			return self::ret_message('requestTokenFailed');
		}

		//sessionkey暂时没用到
		$sessionKey = $reqData['session_key'];

		$signature2 = sha1($rawData.$sessionKey);

		if($signature2!==$signature){
			return self::ret_message("signNotMatch");
		}

		$pc = new wxBizDataCrypt($this->appid, $sessionKey);
		$errCode = $pc->decryptData($encryptedData, $iv, $data );

		if ($errCode !== 0) {
			return self::ret_message("encryptDataNotMatch");
		}

		$data = json_decode($data, true);

		//用这个
    	// $session3rd = self::randomFormDev(16);
		$session3rd = '123123';

		//吧session3rd作为key，openid和别的作为value存储在session中$data['openId'] . $sessionKey
		//这里设置了过期时间呢
		Cache::set($session3rd,$data['openId'],3600*24);


		//登陆的时候如果没有存在数据库中还要创建用户
		$user = new User();
		$res = $user->where('openid',$data['openId'])->find();
		if(empty($res)){
			$user->data([
				'avatarUrl'=>$data['avatarUrl'],
				'city'=>$data['city'],
				'country'=>$data['country'],
				'province'=>$data['province'],
				'nickName'=>$data['nickName'],
				'gender'=>$data['gender'],
				'openid'=>$data['openId']
			]);
			$user->save();
		}

    	$data['session3rd'] = $session3rd;

		return $data;
	}

	//获取openid使用
	public function getCache(Request $request){
		$session3rd = $request->param('session3rd');
		return Cache::get($session3rd);
	}

	public function test(){
		$user = new User();
		$res = $user->where('openid','122')->find();
		return $res;
	}

	function makeRequest($url,$params = array(),$expire = 0,$extend = array(),$hostIp=''){

		if(empty($url)){
			return array('code'=>'100');
		}

		$_curl = curl_init();

		$_header = array(
			'Accept-Language:zh-CN',
			'Connection:Keep-Alive',
			'Cache-Control:no-cache'
		);

		if(!empty($hostIp)){
			$urlInfo = parse_url($url);
			if(empty($urlInfo)){
				$urlInfo['host'] = substr(DOMAIN, 7, -1);
				$url = "http://{$hostIp}{$url}";
			}else{
				$url = str_replace($urlInfo['host'], $hostIp, $url);
			}
			$_header[] = "Host: {$urlInfo['host']}";
		}


		if (!empty($params)) {
			curl_setopt($_curl, CURLOPT_POSTFIELDS, http_build_query($params));
			curl_setopt($_curl, CURLOPT_POST, true);
		}

		if (substr($url, 0, 8) == 'https://') {
			curl_setopt($_curl, CURLOPT_SSL_VERIFYPEER, FALSE);
			curl_setopt($_curl, CURLOPT_SSL_VERIFYHOST, FALSE);
		}
		curl_setopt($_curl, CURLOPT_URL, $url);
		curl_setopt($_curl, CURLOPT_RETURNTRANSFER, true);
		curl_setopt($_curl, CURLOPT_USERAGENT, 'API PHP CURL');
		curl_setopt($_curl, CURLOPT_HTTPHEADER, $_header);

		if ($expire > 0) {
        curl_setopt($_curl, CURLOPT_TIMEOUT, $expire); // 处理超时时间
        curl_setopt($_curl, CURLOPT_CONNECTTIMEOUT, $expire); // 建立连接超时时间
    }

    // 额外的配置
    if (!empty($extend)) {
    	curl_setopt_array($_curl, $extend);
    }

    $result['result'] = curl_exec($_curl);
    $result['code'] = curl_getinfo($_curl, CURLINFO_HTTP_CODE);
    $result['info'] = curl_getinfo($_curl);
    if ($result['result'] === false) {
    	$result['result'] = curl_error($_curl);
    	$result['code'] = -curl_errno($_curl);
    }

    curl_close($_curl);
    return $result;

}

    //返回信息的处理
function ret_message($message = ""){
	if($message == ""){
		return ['result'=>0,'message'=>''];
	}
	$ret = lang($message);

	if(count($ret) !=2 ){
		return ['result'=>-1,'message'=>$ret];
	}
	return ['result'=>$ret[0],'message'=>$ret[1]];
}


//读取/dev/urandom获取随机数
function randomFormDev($len){
	$fp = @fopen('/dev/urandom','rb');
	$result = '';
	if($fp!=FALSE){
		$result .=@fread($fp,$len);
		@fclose($fp);
	}else{
		 trigger_error('Can not open /dev/urandom.');
	}

	 $result = base64_encode($result);

	 $result = strtr($result, '+/', '-_');

	 return substr($result, 0, $len);

}

}
