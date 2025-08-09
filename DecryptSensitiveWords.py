import re
import json
from Crypto.Cipher import ARC4
import base64
import requests

def decode_pcre_unicode_in_obj(obj):
    """
    递归地遍历Python对象 (字典或列表)，并解码其中字符串值的
    PCRE风格Unicode转义 (\\x{...})。

    :param obj: 可能是字典、列表、字符串或其他类型的Python对象。
    :return: 处理过的对象。
    """
    if isinstance(obj, dict):
        # 如果是字典，递归处理它的每个值
        return {k: decode_pcre_unicode_in_obj(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        # 如果是列表，递归处理它的每个元素
        return [decode_pcre_unicode_in_obj(elem) for elem in obj]
    elif isinstance(obj, str):
        # 如果是字符串，执行替换操作
        def replace_match(match):
            hex_code = match.group(1)
            return chr(int(hex_code, 16))

        return re.sub(r'\\x\{([0-9a-fA-F]+)\}', replace_match, obj)
    else:
        # 其他类型（如数字、布尔值）直接返回
        return obj


def decrypt_and_load_sdk_file(encrypted_Content, secret_key):
    """
    解密SDK的加密配置文件，并将其加载为Python对象 (修正版)。

    流程:
    1. 读取和解密文件。
    2. 解析JSON字符串 (让json库处理标准转义)。
    3. 递归解码PCRE风格的Unicode转义。

    :param encrypted_file_path: 加密文件的路径。
    :param secret_key: 用于RC4解密的bytes类型密钥。
    :return: 包含配置的Python字典，如果失败则返回None。
    """
    try:
        # 1. 解密文件
        encrypted_data = base64.b64decode(encrypted_Content)
        cipher = ARC4.new(secret_key)
        decrypted_data_bytes = cipher.decrypt(encrypted_data)

        # 将解密后的bytes转换为字符串 (通常是utf-8)
        decrypted_string_raw = decrypted_data_bytes.decode('utf-8')

        # 2. 先解析JSON
        print("[*] Parsing the decrypted string as JSON...")
        # json.loads 会处理好所有的标准转义，如 \\, \", \n 等
        config_data_raw = json.loads(decrypted_string_raw)

        # 3. 在解析后的Python对象上，递归解码 \x{...}
        # print("[*] Recursively decoding PCRE-style Unicode escapes...")
        final_config_data = decode_pcre_unicode_in_obj(config_data_raw)

        print("\n[SUCCESS] File decrypted and loaded successfully!")
        return final_config_data
    except (base64.binascii.Error, ValueError) as e:
        print(f"[ERROR] Base64 decoding failed: {e}")
        return None
    except UnicodeDecodeError as e:
        print(f"[ERROR] UTF-8 decoding of decrypted content failed: {e}")
        return None
    except json.JSONDecodeError as e:
        # 这里的错误现在是真正的JSON格式错误
        print(f"[ERROR] JSON parsing failed. The decrypted content is not valid JSON: {e}")
        # 打印出原始的、未处理的字符串，帮助调试
        print("\n--- Raw Decrypted String (for debugging) ---")
        #print(decrypted_string_raw)
        print("--------------------------------------------")
        return None
    except Exception as e:
        print(f"[ERROR] An unexpected error occurred: {e}")
        return None


if __name__ == '__main__':
    # --- 使用示例 ---
    # 获取敏感词库url
    # 请求获取url
    BuildPostJson_x19 = {"version":"2.4.0.161787","sys":"windows","deviceid":"AA85-636D-18B2-3937-834B-D59E","gameid":"x19","network":"wifi","info":{}}
    BuildPostJson_g79 = {"version":"2.4.0.161787","sys":"windows","deviceid":"AA85-636D-18B2-3937-834B-D59E","gameid":"g79","network":"wifi","info":{}}
    GetX19Url = requests.post("http://optsdk.gameyw.netease.com/initbox_x19.html",data=base64.b64encode(json.dumps(BuildPostJson_x19).encode('utf-8')).decode("utf-8"),headers={"Content-Type": "application/x-www-form-urlencoded"},verify=False).json()["url"]
    GetG79Url = requests.post("http://optsdk.gameyw.netease.com/initbox_g79.html",data=base64.b64encode(json.dumps(BuildPostJson_g79).encode('utf-8')).decode("utf-8"),headers={"Content-Type": "application/x-www-form-urlencoded"},verify=False).json()["url"]
    GetX19EncryptedContent = requests.get(GetX19Url,verify=False).content
    GetG79EncryptedContent = requests.get(GetG79Url,verify=False).content
    X19Key = "c42bf7f39d479999"
    G79Key = "c42bf7f39d476db3"
    # 解密并保存文件: G79SensitiveWords.json X19SensitiveWords.json
    X19DecryptedData = decrypt_and_load_sdk_file(GetX19EncryptedContent, X19Key.encode('utf-8'))
    G79DecryptedData = decrypt_and_load_sdk_file(GetG79EncryptedContent, G79Key.encode('utf-8'))
    with open("X19SensitiveWords.json", "w", encoding="utf-8") as f:
        json.dump(X19DecryptedData, f, ensure_ascii=False, indent=4)
    with open("G79SensitiveWords.json", "w", encoding="utf-8") as f:
        json.dump(G79DecryptedData, f, ensure_ascii=False, indent=4)
