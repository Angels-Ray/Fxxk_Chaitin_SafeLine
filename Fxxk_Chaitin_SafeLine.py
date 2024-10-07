import base64
import hashlib
from typing import Any, Dict
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import json
import requests

Encrypted_Base_URL = "aHR0cHM6Ly9jaGFsbGVuZ2Uucml2ZXJzLmNoYWl0aW4uY24="
Base_Url = base64.b64decode(Encrypted_Base_URL).decode()

class Fxxk_Chaitin_SafeLine:
    """
    Fxxk SafeLine. 
    共三个cookie:
        sl-session
        sl_waf_recap (中间值, jwt)
        sl_jwt_session

    方法:
        首先访问目标网址, 获取session与once_id, 使用 get_a_jwt(once_id) 获取jwt, 将jwt作为sl_waf_recap与sl-session请求目标网址获取sl_jwt_session
        请求目标网址        ->  响应头获取 sl-session, 响应体获取 once_id 
        请求seed接口        ->  响应体获取 seed
        (获取sdk.js文件, 计算inspect请求体明文的salt + 密文)
        请求inspect接口     ->  响应体获取 sl_waf_recap (中间值, jwt)
        请求目标网址        ->  响应头获取 sl_jwt_session

    """
    @staticmethod
    def get_seed(once_id: str) -> str:
        url = f"{Base_Url}/captcha/api/seed"
        params = {
            "once_id": once_id,
            "v": "1.0.0",
            "hints": "languages,permHook,webDriverValue,vendor,webdriver,headless,globalThis"
        }
        response = requests.get(url, params=params)
        response.raise_for_status()
        return response.json()["seed"]

    @staticmethod
    def get_salt(seed: str, zero_bits: int = 20) -> int:
        for nonce in range(int(1e8)):
            hash_hex = hashlib.sha256(
                (str(seed) + str(nonce)).encode('utf-8')).hexdigest()

            zeros = 0
            for char in hash_hex:
                if char != '0':
                    zeros += 4 - len(bin(int(char, 16))[2:])
                    break
                zeros += 4

            if zeros >= zero_bits:
                return nonce

        return 0

    @staticmethod
    def get_inspect_encrypted_body(seed: str, salt: str) -> str:
        body_dict: Dict[str, Any] = {
            "resolution": "1536x864",
            "languages": ["zh-CN", "zh", "en"],
            "useragents": ["Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36"] * 3,
            "hint": 0,
            "salt": salt,
            "taketime": 3915
        }
        body_json = json.dumps(body_dict, separators=(',', ':'))
        key = seed.ljust(16, '0').encode()
        iv = b'1234567890123456'
        cipher = AES.new(key, AES.MODE_CBC, iv)
        padded_data = pad(body_json.encode(), AES.block_size)
        return cipher.encrypt(padded_data).hex()

    @staticmethod
    def get_sl_waf_recap(seed: str, encrypted_body: str) -> str:
        url = f"{Base_Url}/captcha/api/inspect?seed={seed}"
        response = requests.post(url,  data=encrypted_body)
        response.raise_for_status()
        return response.json()["jwt"]

    def get_a_jwt(self, once_id: str) -> str:
        seed = self.get_seed(once_id)
        salt = self.get_salt(seed, 16)
        encrypted_body = self.get_inspect_encrypted_body(seed, str(salt))
        return self.get_sl_waf_recap(seed, encrypted_body)


if __name__ == "__main__":
    try:
        once_id = "1307bca2fd4c45fc85e75571f4c8ef4e_27"
        fxxk = Fxxk_Chaitin_SafeLine()
        jwt = fxxk.get_a_jwt(once_id)
        print("获取的jwt:", jwt)
    except Exception as e:
        print(f"发生错误: {e}")

