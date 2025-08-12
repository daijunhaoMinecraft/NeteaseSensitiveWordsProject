# update_script.py
# 功能：自动解密、对比、更新网易敏感词，并生成变化报告
# 作者：Qwen + 你
# 用途：配合 GitHub Actions 自动化运行

import re
import json
import base64
import requests
from Crypto.Cipher import ARC4
import os
from deepdiff import DeepDiff
from hashlib import md5
from datetime import datetime

# ========== 配置 ==========
CACHE_FILE = "last_urls.json"        # 缓存上一次的 URL 和哈希
CHANGELOG_MD = "CHANGELOG.md"        # 人类可读的变化报告
CHANGELOG_JSON = "changes.json"      # 机器可读的结构化差异
GITHUB_OWNER = "daijunhaoMinecraft"
GITHUB_REPO = "NeteaseSensitiveWordsProject"
GITHUB_BRANCH = "main"

# ========== 工具函数 ==========

def decode_pcre_unicode_in_obj(obj):
    """
    Recursively decode strings with PCRE-style Unicode escape sequences (e.g., \\x{abcd}).
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
    """解密并返回字典"""
    try:
        encrypted_data = base64.b64decode(encrypted_content)
        cipher = ARC4.new(key.encode('utf-8'))
        decrypted_data = cipher.decrypt(encrypted_data)
        raw_text = decrypted_data.decode('utf-8')
        parsed = json.loads(raw_text)
        return decode_pcre_unicode_in_obj(parsed)
    except Exception as e:
        print(f"[ERROR] 解密失败: {e}")
        raise

def load_cache():
    """加载上一次的状态（URL + 哈希）"""
    if os.path.exists(CACHE_FILE):
        try:
            with open(CACHE_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
            # 补全缺失字段
            for key in ["x19_url", "g79_url", "x19_hash", "g79_hash"]:
                if key not in data:
                    data[key] = None
            return data
        except Exception as e:
            print(f"[WARN] 无法读取缓存文件: {e}")
    return {"x19_url": None, "g79_url": None, "x19_hash": None, "g79_hash": None}

def save_cache(x19_url, g79_url, x19_hash, g79_hash):
    """保存当前状态"""
    with open(CACHE_FILE, "w", encoding="utf-8") as f:
        json.dump({
            "x19_url": x19_url,
            "g79_url": g79_url,
            "x19_hash": x19_hash,
            "g79_hash": g79_hash,
            "updated_at": datetime.now().isoformat()
        }, f, ensure_ascii=False, indent=4)

def hash_json(data):
    """生成 JSON 内容的稳定哈希"""
    return md5(json.dumps(data, sort_keys=True, ensure_ascii=False, separators=(',', ':')).encode('utf-8')).hexdigest()

def get_file_sha(owner, repo, path, token, branch="main"):
    """获取文件当前 SHA"""
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
            return None
        else:
            print(f"[ERROR] 获取 SHA 失败: {resp.status_code}")
            return None
    except Exception as e:
        print(f"[ERROR] 请求失败: {e}")
        return None

def update_github_file(owner, repo, filepath, content, token, branch="main", commit_msg="Auto update"):
    """创建或更新 GitHub 文件"""
    url = f"https://api.github.com/repos/{owner}/{repo}/contents/{filepath}"
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github.v3+json"
    }

    sha = get_file_sha(owner, repo, filepath, token, branch)
    encoded_content = base64.b64encode(content.encode('utf-8')).decode('utf-8')
    payload = {"message": commit_msg, "content": encoded_content, "branch": branch}
    if sha:
        payload["sha"] = sha

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

def diff_path_to_value(diff, path, old=False):
    """从 deepdiff 路径提取值用于显示"""
    try:
        keys = path.strip("root[").split("][")
        value = diff
        for k in keys:
            k = k.strip("'\"")
            if isinstance(value, dict):
                value = value.get(k)
            elif isinstance(value, list) and k.isdigit():
                value = value[int(k)]
            else:
                value = None
        return str(value)[:200]  # 截断过长内容
    except:
        return "unknown"

def generate_changes_report(differences):
    """
    生成统一的变化报告
    :param differences: [(filename, diff_dict), ...]，其中 diff_dict 是 DeepDiff 对象
    """
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    if not differences:
        # 无变化
        md_content = f"# 📝 敏感词更新报告 - {timestamp}\n\n✅ 本次运行未检测到任何内容变化。\n"
        json_report = {
            "timestamp": datetime.now().isoformat(),
            "total_files_changed": 0,
            "changes": []
        }
    else:
        # 有变化
        md_content = f"# 📝 敏感词更新报告 - {timestamp}\n\n"
        md_content += "本次检测到以下文件发生变化：\n\n"
        json_changes = []

        for filename, diff in differences:
            # ✅ 关键修复：使用 to_dict() 转为原生字典
            diff_dict = diff.to_dict() if hasattr(diff, 'to_dict') else dict(diff)

            md_content += f"## 📄 `{filename}`\n\n"
            json_change = {"file": filename, "diff": diff_dict}
            has_change = False

            # 新增
            added = diff_dict.get("dictionary_item_added", [])
            if added:
                md_content += "### ➕ 新增规则\n"
                for item in added:
                    md_content += f"- `{item}`: {diff_path_to_value(diff, item)}\n"
                md_content += "\n"
                has_change = True

            # 删除
            removed = diff_dict.get("dictionary_item_removed", [])
            if removed:
                md_content += "### ❌ 删除规则\n"
                for item in removed:
                    md_content += f"- `{item}`: {diff_path_to_value(diff, item, old=True)}\n"
                md_content += "\n"
                has_change = True

            # 修改
            changed = diff_dict.get("values_changed", {})
            if changed:
                md_content += "### 🔁 修改规则\n"
                for key, change in changed.items():
                    old = change.get('old_value', 'N/A')
                    new = change.get('new_value', 'N/A')
                    md_content += f"- `{key}`: `{old}` → `{new}`\n"
                md_content += "\n"
                has_change = True

            # 类型变更
            type_changed = diff_dict.get("type_changes", {})
            if type_changed:
                md_content += "### ⚠️ 类型变更\n"
                for key, change in type_changed.items():
                    old_t = change.get('old_type', 'N/A')
                    new_t = change.get('new_type', 'N/A')
                    md_content += f"- `{key}`: `{old_t}` → `{new_t}`\n"
                md_content += "\n"
                has_change = True

            if not has_change:
                md_content += "ℹ️ 无显著变化（可能为顺序调整）\n\n"

            json_changes.append(json_change)

        json_report = {
            "timestamp": datetime.now().isoformat(),
            "total_files_changed": len(differences),
            "changes": json_changes
        }

    # ✅ 写入文件
    with open(CHANGELOG_MD, "w", encoding="utf-8") as f:
        f.write(md_content)

    with open(CHANGELOG_JSON, "w", encoding="utf-8") as f:
        # ✅ 确保 JSON 可序列化
        json.dump(json_report, f, ensure_ascii=False, indent=4)

    print(f"[INFO] 变化报告已生成：{CHANGELOG_MD} 和 {CHANGELOG_JSON}")

# ========== 主函数 ==========

def main():
    print("[+] 开始更新敏感词数据...")

    GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
    if not GITHUB_TOKEN:
        raise Exception("❌ GITHUB_TOKEN 未设置！请检查 Actions Secrets。")

    # 加载缓存
    cache = load_cache()
    old_x19_url = cache.get("x19_url")
    old_g79_url = cache.get("g79_url")

    files_to_update = []
    differences = []  # 收集所有差异

    try:
        # --- 获取新 URL ---
        build_json_x19 = {
            "version": "2.4.0.161787",
            "sys": "windows",
            "deviceid": "AA85-636D-18B2-3937-834B-D59E",
            "gameid": "x19",
            "network": "wifi",
            "info": {}
        }
        build_json_g79 = build_json_x19.copy()
        build_json_g79["gameid"] = "g79"

        x19_resp = requests.post(
            "http://optsdk.gameyw.netease.com/initbox_x19.html",
            data=base64.b64encode(json.dumps(build_json_x19).encode('utf-8')).decode('utf-8'),
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            verify=False
        )
        x19_resp.raise_for_status()
        x19_data = x19_resp.json()
        if "url" not in x19_data:
            raise Exception(f"响应中无 'url' 字段: {x19_data}")
        x19_url = x19_data["url"]

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

        # --- 检查 URL 是否变化 ---
        if x19_url == old_x19_url and g79_url == old_g79_url:
            print("[INFO] URLs 未变化，无需更新。")
            generate_changes_report([])  # 生成空报告
            return

        print("[*] URLs 发生变化，准备下载新内容...")

        # --- 下载并解密 ---
        x19_encrypted = requests.get(x19_url, verify=False).content
        g79_encrypted = requests.get(g79_url, verify=False).content

        x19_data = decrypt_content(x19_encrypted, "c42bf7f39d479999")
        g79_data = decrypt_content(g79_encrypted, "c42bf7f39d476db3")

        x19_hash = hash_json(x19_data)
        g79_hash = hash_json(g79_data)

        # --- 比较内容变化 ---
        for name, new_data, old_hash, url in [
            ("X19SensitiveWords.json", x19_data, cache.get("x19_hash"), x19_url),
            ("G79SensitiveWords.json", g79_data, cache.get("g79_hash"), g79_url)
        ]:
            old_data = None
            if os.path.exists(name):
                try:
                    with open(name, "r", encoding="utf-8") as f:
                        old_data = json.load(f)
                except Exception as e:
                    print(f"[WARN] 无法读取旧文件 {name}: {e}")

            if old_data is None:
                print(f"[INFO] 首次运行或 {name} 不存在，视为新增。")
                files_to_update.append((name, new_data, url))
                differences.append((name, {"initial_create": True}))
            else:
                diff = DeepDiff(old_data, new_data, ignore_order=True)
                if diff:
                    print(f"[*] {name} 内容发生变化！")
                    files_to_update.append((name, new_data, url))
                    differences.append((name, diff))
                else:
                    print(f"[INFO] {name} 内容未变化（基于哈希或结构对比），跳过。")

        # --- 生成统一变化报告 ---
        generate_changes_report(differences)

        # --- 仅当有文件要更新时才提交 ---
        if not files_to_update:
            print("[INFO] 所有文件均无实质变化，无需提交。")
            save_cache(x19_url, g79_url, x19_hash, g79_hash)
            return

        # --- 更新 GitHub 文件 ---
        all_success = True
        for filename, data, url in files_to_update:
            content = json.dumps(data, ensure_ascii=False, indent=4)
            success = update_github_file(
                owner=GITHUB_OWNER,
                repo=GITHUB_REPO,
                filepath=filename,
                content=content,
                token=GITHUB_TOKEN,
                branch=GITHUB_BRANCH,
                commit_msg=f"🔄 Update {filename} (source updated)"
            )
            if success:
                with open(filename, "w", encoding="utf-8") as f:
                    f.write(content)
            all_success &= success

        if all_success:
            print("\n🎉 所有变更文件已成功更新！")
            save_cache(x19_url, g79_url, x19_hash, g79_hash)
        else:
            print("\n❌ 更新失败。")
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
