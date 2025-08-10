# update_script.py
# 功能：自动解密网易敏感词配置并更新到 GitHub 仓库
# 作者：Qwen + 你
# 用途：配合 GitHub Actions 自动化运行

import re
import json
import base64
import requests
from Crypto.Cipher import ARC4
import os

def decode_pcre_unicode_in_obj(obj):
    """
    Recursively decode strings with PCRE-style Unicode escape sequences (e.g., \\x{abcd}).
    递归处理对象中的字符串，将形如 \\x{abcd} 的 Unicode 转义替换为对应字符。
    """
    if isinstance(obj, dict):
        return {k: decode_pcre_unicode_in_obj(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [decode_pcre_unicode_in_obj(elem) for elem in obj]
    elif isinstance(obj, str):
        def replace_match(match):
            hex_code = match.group(1)
            return chr(int(hex_code, 16))
        return re.sub(r'\\x\{([0-9a-fA-F]+)\}', replace_match, obj)
    else:
        return obj

def decrypt_content(encrypted_content: bytes, key: str) -> dict:
    """解密内容并返回字典"""
    try:
        # Base64 解码
        encrypted_data = base64.b64decode(encrypted_content)
        # RC4 解密
        cipher = ARC4.new(key.encode('utf-8'))
        decrypted_data = cipher.decrypt(encrypted_data)
        # 转为字符串
        raw_text = decrypted_data.decode('utf-8')
        # JSON 解析
        parsed = json.loads(raw_text)
        # 递归解码 \x{...}
        return decode_pcre_unicode_in_obj(parsed)
    except Exception as e:
        print(f"[ERROR] 解密失败: {e}")
        raise

def get_file_sha(owner: str, repo: str, path: str, token: str, branch: str = "main") -> str | None:
    """获取文件当前 SHA（用于更新）"""
    # 🔴 修复：删除了 URL 中多余的空格
    url = f"https://api.github.com/repos/{owner}/{repo}/contents/{path}"
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github.v3+json"
    }
    params = {"ref": branch}
    try:
        resp = requests.get(url, headers=headers, params=params)
        if resp.status_code == 200:
            return resp.json()["sha"]
        elif resp.status_code == 404:
            print(f"[INFO] 文件 {path} 不存在，将创建。")
            return None
        else:
            print(f"[ERROR] 获取 SHA 失败: {resp.status_code}, {resp.text}")
            return None
    except Exception as e:
        print(f"[ERROR] 请求失败: {e}")
        return None

def update_github_file(
    owner: str,
    repo: str,
    filepath: str,
    content: str,
    token: str,
    branch: str = "main",
    commit_msg: str = "Auto update file"
):
    """通过 GitHub API 创建或更新文件"""
    # 🔴 修复：删除了 URL 中多余的空格
    url = f"https://api.github.com/repos/{owner}/{repo}/contents/{filepath}"
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github.v3+json"
    }

    # 获取当前文件 SHA（更新需要）
    sha = get_file_sha(owner, repo, filepath, token, branch)

    # 准备 payload
    encoded_content = base64.b64encode(content.encode('utf-8')).decode('utf-8')
    payload = {
        "message": commit_msg,
        "content": encoded_content,
        "branch": branch
    }
    if sha:
        payload["sha"] = sha

    # 发送 PUT 请求
    resp = requests.put(url, headers=headers, json=payload)
    if resp.status_code in (200, 201):
        print(f"[SUCCESS] 成功更新 {filepath}")
        return True
    else:
        print(f"[ERROR] 更新失败 {filepath}: {resp.status_code}")
        try:
            print(resp.json())
        except:
            print(resp.text)
        return False

def main():
    print("[+] 开始更新敏感词数据...")

    # --- 配置 ---
    GITHUB_OWNER = "daijunhaoMinecraft"
    GITHUB_REPO = "NeteaseSensitiveWordsProject"
    GITHUB_BRANCH = "main"
    GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")  # 从环境变量读取

    if not GITHUB_TOKEN:
        raise Exception("❌ GITHUB_TOKEN 未设置！请检查 Actions Secrets。")

    # --- 获取加密数据 ---
    try:
        # 构造请求参数
        build_json_x19 = {
            "version": "2.4.0.161787",
            "sys": "windows",
            "deviceid": "AA85-636D-18B2-3937-834B-D59E",
            "gameid": "x19",
            "network": "wifi",
            "info": {}
        }

        # ✅ 修复：正确复制字典，而不是 {dict} 创建 set
        build_json_g79 = build_json_x19.copy()  # 或 dict(build_json_x19)
        build_json_g79["gameid"] = "g79"

        # 获取 x19 URL
        x19_resp = requests.post(
            "http://optsdk.gameyw.netease.com/initbox_x19.html",
            data=base64.b64encode(json.dumps(build_json_x19).encode('utf-8')).decode('utf-8'),
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            verify=False
        )
        x19_resp.raise_for_status()  # 检查 HTTP 错误
        x19_data = x19_resp.json()
        if "url" not in x19_data:
            raise Exception(f"响应中无 'url' 字段: {x19_data}")
        x19_url = x19_data["url"]

        # 获取 g79 URL
        g79_resp = requests.post(
            "http://optsdk.gameyw.netease.com/initbox_g79.html",
            data=base64.b64encode(json.dumps(build_json_g79).encode('utf-8')).decode('utf-8'),
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            verify=False
        )
        g79_resp.raise_for_status()
        g79_data = g79_resp.json()
        if "url" not in g79_data:
            raise Exception(f"响应中无 'url' 字段: {g79_data}")
        g79_url = g79_data["url"]

        # 下载加密内容
        print("[*] 下载加密文件...")
        x19_encrypted = requests.get(x19_url, verify=False).content
        g79_encrypted = requests.get(g79_url, verify=False).content

        # 解密
        print("[*] 解密中...")
        x19_data = decrypt_content(x19_encrypted, "c42bf7f39d479999")
        g79_data = decrypt_content(g79_encrypted, "c42bf7f39d476db3")

        # 格式化为 JSON 字符串
        x19_content = json.dumps(x19_data, ensure_ascii=False, indent=4)
        g79_content = json.dumps(g79_data, ensure_ascii=False, indent=4)

        # --- 更新到 GitHub ---
        print("[*] 正在更新 GitHub 文件...")
        success1 = update_github_file(
            owner=GITHUB_OWNER,
            repo=GITHUB_REPO,
            filepath="X19SensitiveWords.json",
            content=x19_content,
            token=GITHUB_TOKEN,
            branch=GITHUB_BRANCH,
            commit_msg="🤖 Auto update X19 sensitive words"
        )

        success2 = update_github_file(
            owner=GITHUB_OWNER,
            repo=GITHUB_REPO,
            filepath="G79SensitiveWords.json",
            content=g79_content,
            token=GITHUB_TOKEN,
            branch=GITHUB_BRANCH,
            commit_msg="🤖 Auto update G79 sensitive words"
        )

        if success1 and success2:
            print("\n🎉 所有文件更新成功！")
        else:
            print("\n❌ 更新失败，请检查日志。")
            exit(1)

    except requests.exceptions.RequestException as e:
        print(f"\n[NETWORK ERROR] 网络请求失败: {e}")
        exit(1)
    except json.JSONDecodeError as e:
        print(f"\n[JSON ERROR] JSON 解析失败: {e}")
        exit(1)
    except Exception as e:
        print(f"\n[CRITICAL] 执行失败: {e}")
        exit(1)

if __name__ == "__main__":
    main()
