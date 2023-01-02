<?php
class MSL {
	public $identity = 'NFCDCH-LX-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxx';
	public $private_key;
	public $public_key;
	public $encription_key;
	public $hmac_key;
	public $session_str;
	public $credentials = array();
	public $user_id = '';
	public $cookie = '';

	function create_keys() {
		$filename = __DIR__ .'/msl_pk.pem';
		if (file_exists($filename)) {
			$pem = file_get_contents($filename);
			$this->private_key = openssl_pkey_get_private($pem);
		} else {
			$config = array("digest_alg" => "sha512", "private_key_bits" => 2048, "private_key_type" => OPENSSL_KEYTYPE_RSA);
			$this->private_key = openssl_pkey_new($config);
			openssl_pkey_export_to_file($this->private_key, $filename);
		}
		$public_key = openssl_pkey_get_details($this->private_key);
		$this->public_key = $public_key['key'];
	}

	function pem_to_der($key) {
		$key = str_replace('-----BEGIN PUBLIC KEY-----', '', $key);
		$key = str_replace('-----END PUBLIC KEY-----', '', $key);
		$key = str_replace("\n", '', $key);
		return $key;
	}

	function post($data, $close = true) {
		$user_agent = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Safari/537.36";
		$opts = array('http' =>
		  array(
		    'method'  => 'POST',
		    'header'  => "User-Agent: $user_agent\r\n" .
		                 "Content-type: text/plain\r\n".
		                 //"Cookie: ". $this->cookie ."\r\n".
		                 "Host: www.netflix.com\r\n".
		                 "Referer: https://www.netflix.com\r\n".
		                 "Accept: */*\r\n" .
		                 //"Accept-Encoding: gzip, deflate, br\r\n".
		                 "Connection: close\r\n" .
		                 "DNT: 1\r\n".
		                 "Content-length: " . strlen($data) ."\r\n",
		    'content' => $data
		  )
		);

		//$url = 'https://www.netflix.com/nq/msl_v1/cadmium/pbo_manifests/%5E1.0.0/router?reqAttempt=1&reqPriority=0&reqName=manifest';
		$url = 'https://www.netflix.com/msl/playapi/cadmium/licensedmanifest/1?reqAttempt=1&reqName=licensedManifest&clienttype=akira&uiversion=ve916f907&browsername=chrome&browserversion=107.0.0.0&osname=linux&osversion=0.0.0';

		$context  = stream_context_create($opts);
		$result = file_get_contents($url, false, $context);
		return $result;
	}

	function sign($text) {
		$hmac_key = base64_decode($this->hmac_key);
		$signature = base64_encode(hash_hmac('sha256', $text , $hmac_key, true));
		return $signature;
	}

	function generate_iv() {
		return base64_encode(openssl_random_pseudo_bytes(16));
	}


	function request_handshake() {
		echo "Handshake: ESN: ". $this->identity ."\n";
		$cache_filename = __DIR__ .'/'. $this->identity . '_handshake.json';
		if (file_exists($cache_filename)) {
			$res = file_get_contents($cache_filename);
			return $res;
		}

		$messageid = mt_rand();

		$header = '{"messageid":'. $messageid .',"renewable":true,'.
            '"capabilities":{"compressionalgos":[],"languages":[]},'.
            '"keyrequestdata":[{"scheme":"ASYMMETRIC_WRAPPED","keydata":'.
            '{"keypairid":"rsaKeypairId","mechanism":"JWK_RSA",'.
            '"publickey":"'. $this->pem_to_der($this->public_key) .'"}}]}';

		$payload = '{"sequencenumber":1,"messageid":'. $messageid .',"endofmsg":true,"data":""}';

		$env = '{"entityauthdata":{"scheme":"NONE","authdata":{"identity":"'. $this->identity .'"}},'.
           '"headerdata":"'. base64_encode($header) .'","signature":""}'.
           '{"payload":"'. base64_encode($payload) .'","signature":""}';

		$res = $this->post($env);
		file_put_contents($cache_filename, $res);
		return $res;
	}

	function request_manifest($title_id) {
		$encryption_key = $this->encryption_key;

		$messageid = mt_rand();

		$iv = $this->generate_iv();

		$plaintext = '{"handshake": false, "sender": "'. $this->identity .'", '.
             '"timestamp": '. time() .', "capabilities": {"languages": ["es-ES"], '.
             '"compressionalgos": ["GZIP"]}, ';

		if (empty($this->user_id)) {
			$plaintext .=
             '"userauthdata": {"authdata": '.
             '{"password": "'. $this->credentials['password'] .'", "email": "'. $this->credentials['username'] .'"}, '.
             '"scheme": "EMAIL_PASSWORD"},';
		} else {
			$plaintext .= '"useridtoken": '. $this->user_id .',';
		}

		$plaintext .= ' "messageid": '. $messageid .', "recipient": "Netflix", "renewable": true}';

		$t = openssl_encrypt($plaintext, 'AES-128-CBC', base64_decode($encryption_key), 0, base64_decode($iv));

		$headerdata = '{"sha256": "AA==", "ciphertext": "'. $t .'", "keyid": "'. $this->identity .'_6", "iv": "'. $iv .'"}';

		$iv = $this->generate_iv();

        $data = [
            "version" => 2,
            "url" => "licensedManifest",
            "id" => intval(microtime(true)*100000000),
            "languages" => ["es-ES"],
            "params" => [
                "type" => "standard",
                "manifestVersion" => "v2",
                "viewableId" => $title_id,
                "profiles" => [
                    "heaac-2-dash",
                    "heaac-2hq-dash",
                    "playready-h264mpl30-dash",
                    "playready-h264mpl31-dash",
                    "playready-h264mpl40-dash",
                    "playready-h264hpl30-dash",
                    "playready-h264hpl31-dash",
                    "playready-h264hpl40-dash",
                    "h264hpl30-dash-playready-live",
                    "h264hpl31-dash-playready-live",
                    //"vp9-profile0-L30-dash-cenc",
                    //"vp9-profile0-L31-dash-cenc",
                    "dfxp-ls-sdh",
                    "simplesdh",
                    "nflx-cmisc",
                    "imsc1.1",
                    "BIF240",
                    "BIF320",
                ],
                "flavor" => "PRE_FETCH",
                "drmType" => "widevine",
                "drmVersion" => 25,
                "usePsshBox" => true,
                "isBranching" => false,
                "useHttpsStreams" => true,
                "supportsUnequalizedDownloadables" => true,
                "imageSubtitleHeight" => 720,
                "uiVersion" => "shakti-vf9f926cd",
                "uiPlatform" => "SHAKTI",
                "clientVersion" => "6.0038.217.911",
                "platform" => "106.0.0",
                "osVersion" => "0.0.0",
                "osName" => "linux",
                "supportsPreReleasePin" => true,
                "supportsWatermark" => true,
                "videoOutputInfo" => [
                    [
                        "type" => "DigitalVideoOutputDescriptor",
                        "outputType" => "unknown",
                        "supportedHdcpVersions" => [],
                        "isHdcpEngaged" => false,
                    ],
                ],
                "titleSpecificData" => [$title_id => ["unletterboxed" => false]],
                "preferAssistiveAudio" => false,
                "isUIAutoPlay" => false,
                "isNonMember" => false,
                "desiredVmaf" => "plus_lts",
                "desiredSegmentVmaf" => "plus_lts",
                "requestSegmentVmaf" => false,
                "supportsPartialHydration" => true,
                "contentPlaygraph" => ["start"],
                "liveMetadataFormat" => "INDEXED_SEGMENT_TEMPLATE",
                "useBetterTextUrls" => true,
                "profileGroups" => [
                    [
                        "name" => "default",
                        "profiles" => [
                            "heaac-2-dash",
                            "heaac-2hq-dash",
                            "playready-h264mpl30-dash",
                            "playready-h264mpl31-dash",
                            "playready-h264mpl40-dash",
                            "playready-h264hpl30-dash",
                            "playready-h264hpl31-dash",
                            "playready-h264hpl40-dash",
                            "h264hpl30-dash-playready-live",
                            "h264hpl31-dash-playready-live",
                            //"vp9-profile0-L30-dash-cenc",
                            //"vp9-profile0-L31-dash-cenc",
                            "dfxp-ls-sdh",
                            "simplesdh",
                            "nflx-cmisc",
                            "imsc1.1",
                            "BIF240",
                            "BIF320",
                        ],
                    ],
                ],
                "licenseType" => "limited",
                "xid" => intval(microtime(true)*100000000),
            ],
        ];


		$message = json_encode($data, JSON_UNESCAPED_SLASHES);

		$plaintext = '{"endofmsg": true, "data": "'. base64_encode($message) .'", "sequencenumber": 1, "messageid": '. $messageid .'}';

		$t = openssl_encrypt($plaintext, 'AES-128-CBC', base64_decode($encryption_key), 0, base64_decode($iv));
		$payload = '{"sha256": "AA==", "ciphertext": "'. $t .'", "keyid": "'. $this->identity .'_6", "iv": "'. $iv .'"}';

		$env = '{"mastertoken": '. $this->session_str .
           ', "headerdata":"'. base64_encode($headerdata) .'", "signature": "'. $this->sign($headerdata) .'"}'.
           '{"payload" :"'. base64_encode($payload) .'", "signature": "'. $this->sign($payload) .'"}';

		$res = $this->post($env);
		return $res;
	}

	function decrypt_key($text) {
		$key = '';
		openssl_private_decrypt(base64_decode($text), $dec, $this->private_key,  OPENSSL_PKCS1_OAEP_PADDING);

		$j = json_decode($dec, true);
		if (isset($j['k'])) {
			$key = $j['k'];
			$key = strtr($key, '-_', '+/') . str_repeat('=', 3 - (3 + strlen($key)) % 4);
		}
		return $key;
	}

	function parse_response($r) {
		$d = json_decode($r, true);
		if ($d != NULL) {
			if (isset($d['errordata'])) {
				$error = base64_decode($d['errordata']);
				echo "Error: $error \n";
				return false;
			}
			if (isset($d['headerdata'])) {
				$env = base64_decode($d['headerdata']);
				$data = json_decode($env, true);

				if (isset($data['keyresponsedata']['keydata'])) {
					$text = $data['keyresponsedata']['keydata']['encryptionkey'];
					$this->encryption_key = $this->decrypt_key($text);

					$text = $data['keyresponsedata']['keydata']['hmackey'];
					$this->hmac_key = $this->decrypt_key($text);
				}

				if (isset($data['keyresponsedata']['mastertoken'])) {
					$this->session_str = json_encode($data['keyresponsedata']['mastertoken']);
					$this->save_session();
				}
			}
		}
		return true;
	}

	function parse_payload($r) {
		if (!isset($this->encryption_key)) {
			echo "Error: no encryption key \n";
			return '';
		}

		$encryption_key = $this->encryption_key;
		$res = '';

		$r = str_replace("}{\"payload\":", "}\n{\"payload\":", $r);
		$lines = explode("\n", $r);
		foreach($lines as $l) {
			$d = json_decode($l, true);

			if (isset($d['errordata'])) {
				$error = base64_decode($d['errordata']);
				echo "Error: $error \n";
				return '';
			}

			if (isset($d['payload'])) {
				$env = base64_decode($d['payload']);
				$data = json_decode($env, true);
				if (isset($data['ciphertext'])) {
					$iv = $data['iv'];
					$t = openssl_decrypt($data['ciphertext'], 'AES-128-CBC', base64_decode($encryption_key), 0, base64_decode($iv));
					$data2 = json_decode($t, true);
					if (isset($data2['data'])) {
						$chunk = base64_decode($data2['data']);
						if (isset($data2['compressionalgo'])) {
							if ($data2['compressionalgo'] == 'GZIP') {
								$chunk = file_get_contents('compress.zlib://data:who/cares;base64,'. base64_encode($chunk));
							}
						}
						$res .= $chunk;
					}
				}
			}

			
			if (isset($d['headerdata'])) {
				$env = base64_decode($d['headerdata']);
				$data = json_decode($env, true);
				if (isset($data['ciphertext'])) {
					$iv = $data['iv'];
					$t = openssl_decrypt($data['ciphertext'], 'AES-128-CBC', base64_decode($encryption_key), 0, base64_decode($iv));
					$data2 = json_decode($t, true);
					if (isset($data2['useridtoken']['tokendata'])) {
						$this->user_id = json_encode($data2['useridtoken']);
					}
				}
			}
			
		}

		return $res;
	}


	function save_session() {
		$filename = __DIR__ .'/'. $this->identity .'_session.json';
		$r['session'] = $this->session_str;
		$r['encryption_key'] = $this->encryption_key;
		$r['hmac_key'] = $this->hmac_key;
		file_put_contents($filename, json_encode($r));
	}

	function load_session() {
		$filename = __DIR__ .'/'. $this->identity .'_session.json';
		if (file_exists($filename)) {
			$r = json_decode(file_get_contents($filename), true);
			$this->session_str = $r['session'];
			$this->encryption_key = $r['encryption_key'];
			$this->hmac_key = $r['hmac_key'];
		}
	}

	function is_session_valid() {
		if (empty($this->session_str)) return false;
		$d = json_decode($this->session_str, true);
		if (isset($d['tokendata'])) {
			$str = base64_decode($d['tokendata']);
			$td = json_decode($str, true);
			if (isset($td['expiration'])) {
				return ($td['expiration'] > time());
			}
		}
		return false;
	}

	function init() {
		$credentials_filename = __DIR__ .'/credentials.json';
		if (file_exists($credentials_filename)) {
			$this->credentials = json_decode(base64_decode(file_get_contents($credentials_filename)), true);
		}
		if (empty($this->credentials)) {
			$this->credentials['username'] = readline("Username: ");
			$this->credentials['password'] = readline("Password: ");
			file_put_contents($credentials_filename, base64_encode(json_encode($this->credentials)));
		}

		echo "Creating keys...\n";
		$this->create_keys();

		$this->load_session();
		if ($this->is_session_valid()) {
			return true;
		} else {
			echo "Requesting session...\n";
			$res = $this->request_handshake();
			$ok = $this->parse_response($res);
			return $ok;
		}
	}

	function download_manifest($id, $format = 'xml') {
		echo "Requesting manifest for ID $id...\n";
		$json_data = $this->request_manifest($id);
		$res['manifest'] = $this->parse_payload($json_data);
		return $res;
	}

	function test() {
		$ok = $this->init();
		if ($ok) {
			$id = '80018585';
			$res = $this->download_manifest($id);
			file_put_contents('manifest.json', $res['manifest']);

			$d = json_decode($res['manifest'], true);
			echo "ESN  : ". $this->identity ."\n";
			echo "Video resolution:\n";
			foreach($d['result']['video_tracks'] as $t) {
				foreach($t['streams'] as $st) {
					echo ' '. $st['res_w'] .'x'. $st['res_h'] ."\n";
				}
			}
		}
	}
}

$msl = new MSL();
$msl->test();
?>
