# update_script.py
# 功能：自动解密、对比、更新网易敏感词，并生成变化报告
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
    headers = {"Authorization": f"Bearer {token}", "Accept": "application/vnd.github.v3+json"}
    params = {"ref": branch}
    try:
        resp = requests.get(url, headers=headers, params=params)
        if resp.status_code == 200:
            return resp.json()["sha"]
        elif resp.status_code == 404:
            return None
        resp.raise_for_status()
    except Exception as e:
        print(f"[ERROR] 获取 SHA 失败: {e}")
        return None

def update_github_file(owner, repo, filepath, content, token, branch="main", commit_msg="Auto update"):
    """创建或更新 GitHub 文件"""
    url = f"https://api.github.com/repos/{owner}/{repo}/contents/{filepath}"
    headers = {"Authorization": f"Bearer {token}", "Accept": "application/vnd.github.v3+json"}
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
        print(f"[ERROR] 更新失败 {filepath}: {resp.status_code} - {resp.text}")
        return False

# 【新增】自定义对比函数，解决 ID 变化导致无法正确 diff 的问题
def compare_words_by_content(old_data, new_data):
    """
    通过比较正则表达式的内容而不是不稳定的ID来找出差异。
    返回一个包含'added', 'removed', 'modified'的字典。
    """
    changes = {"added": [], "removed": [], "modified": {}}

    # --- 1. 对比 regex.nickname 部分 ---
    old_regex_dict = old_data.get("regex", {}).get("nickname", {})
    new_regex_dict = new_data.get("regex", {}).get("nickname", {})

    # 创建从 regex 内容到 ID 的反向映射
    old_content_to_id = {v: k for k, v in old_regex_dict.items()}
    new_content_to_id = {v: k for k, v in new_regex_dict.items()}

    old_contents = set(old_content_to_id.keys())
    new_contents = set(new_content_to_id.keys())

    # 找出新增和删除的 regex 内容
    added_contents = new_contents - old_contents
    removed_contents = old_contents - new_contents

    for content in sorted(list(added_contents)):
        changes["added"].append({"id": new_content_to_id[content], "value": content})

    for content in sorted(list(removed_contents)):
        changes["removed"].append({"id": old_content_to_id[content], "value": content})

    # --- 2. 对比文件的其余部分 ---
    # 创建数据的深拷贝，并移除我们已手动处理的部分
    old_data_copy = json.loads(json.dumps(old_data))
    new_data_copy = json.loads(json.dumps(new_data))
    if "nickname" in old_data_copy.get("regex", {}):
        del old_data_copy["regex"]["nickname"]
    if "nickname" in new_data_copy.get("regex", {}):
        del new_data_copy["regex"]["nickname"]
    
    # 使用 DeepDiff 对比剩余的稳定结构
    other_diffs = DeepDiff(old_data_copy, new_data_copy, ignore_order=True)
    if other_diffs:
        changes["modified"] = other_diffs.to_dict()

    # 如果没有任何变化，返回 None
    if not changes["added"] and not changes["removed"] and not changes["modified"]:
        return None
    
    return changes


# 【修复】更新报告生成函数以适应新的差异结构
def generate_changes_report(differences):
    """
    生成统一的变化报告
    :param differences: [(filename, diff_dict, old_data, new_data), ...]
    """
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    if not any(d[1] for d in differences):
        md_content = f"# 📝 敏感词更新报告 - {timestamp}\n\n✅ 本次运行未检测到任何内容变化。\n"
        json_report = {"timestamp": datetime.now().isoformat(), "total_files_changed": 0, "changes": []}
    else:
        md_content = f"# 📝 敏感词更新报告 - {timestamp}\n\n"
        md_content += "本次检测到以下文件发生变化：\n\n"
        json_changes = []

        for filename, diff_dict, old_data, new_data in differences:
            if not diff_dict: continue

            md_content += f"## 📄 `{filename}`\n\n"
            json_change = {"file": filename, "diff": diff_dict}
            has_change = False

            # 新增
            added = diff_dict.get("added", [])
            if added:
                md_content += "### ➕ 新增规则 (by content)\n"
                for item in added:
                    md_content += f"- **ID `{item['id']}`**: `{item['value'][:200]}`\n"
                md_content += "\n"
                has_change = True

            # 删除
            removed = diff_dict.get("removed", [])
            if removed:
                md_content += "### ❌ 删除规则 (by content)\n"
                for item in removed:
                    md_content += f"- **ID `{item['id']}`**: `{item['value'][:200]}`\n"
                md_content += "\n"
                has_change = True

            # 修改（其他字段）
            modified = diff_dict.get("modified", {})
            if modified:
                md_content += "### 🔁 修改其他字段\n"
                changed = modified.get("values_changed", {})
                for key, change in changed.items():
                    old = change.get('old_value', 'N/A')
                    new = change.get('new_value', 'N/A')
                    md_content += f"- `{key}`: `{old}` → `{new}`\n"
                md_content += "\n"
                has_change = True

            if not has_change:
                md_content += "ℹ️ 无显著变化。\n\n"

            json_changes.append(json_change)

        json_report = {
            "timestamp": datetime.now().isoformat(),
            "total_files_changed": len(json_changes),
            "changes": json_changes
        }

    with open(CHANGELOG_MD, "w", encoding="utf-8") as f:
        f.write(md_content)
    with open(CHANGELOG_JSON, "w", encoding="utf-8") as f:
        json.dump(json_report, f, ensure_ascii=False, indent=4)
    print(f"[INFO] 变化报告已生成：{CHANGELOG_MD} 和 {CHANGELOG_JSON}")

# ========== 主函数 ==========

def main():
    print("[+] 开始更新敏感词数据...")
    GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
    if not GITHUB_TOKEN:
        raise Exception("❌ GITHUB_TOKEN 未设置！请检查 Actions Secrets。")

    cache = load_cache()
    files_to_update = []
    differences = []

    try:
        # --- 获取新 URL ---
        requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)
        session = requests.Session()
        session.headers.update({"Content-Type": "application/x-www-form-urlencoded"})
        
        build_json = {"version": "2.4.0.161787", "sys": "windows", "deviceid": "AA85-636D-18B2-3937-834B-D59E", "network": "wifi", "info": {}}
        
        def get_url(game_id):
            payload = build_json.copy()
            payload["gameid"] = game_id
            resp = session.post(
                f"http://optsdk.gameyw.netease.com/initbox_{game_id}.html",
                data=base64.b64encode(json.dumps(payload).encode('utf-8')).decode('utf-8'),
                verify=False
            )
            resp.raise_for_status()
            data = resp.json()
            if "url" not in data:
                raise Exception(f"{game_id} 响应中无 'url' 字段: {data}")
            return data["url"]

        x19_url = get_url("x19")
        g79_url = get_url("g79")
        
        # --- 检查 URL 或哈希是否变化 ---
        if x19_url == cache.get("x19_url") and g79_url == cache.get("g79_url"):
            print("[INFO] URLs 未变化，无需更新。")
            generate_changes_report([])
            return

        print("[*] URLs 发生变化，准备下载新内容...")

        # --- 下载并解密 ---
        x19_data = decrypt_content(session.get(x19_url, verify=False).content, "c42bf7f39d479999")
        g79_data = decrypt_content(session.get(g79_url, verify=False).content, "c42bf7f39d476db3")

        new_x19_hash = hash_json(x19_data)
        new_g79_hash = hash_json(g79_data)

        # 【修复】使用新的对比逻辑
        all_data = [
            ("X19SensitiveWords.json", x19_data, new_x19_hash),
            ("G79SensitiveWords.json", g79_data, new_g79_hash),
        ]

        has_content_changed = False
        for name, new_data, new_hash in all_data:
            old_data = None
            if os.path.exists(name):
                try:
                    with open(name, "r", encoding="utf-8") as f:
                        old_data = json.load(f)
                except Exception as e:
                    print(f"[WARN] 无法读取旧文件 {name}: {e}")
            
            # 使用自定义函数进行内容对比
            diff = compare_words_by_content(old_data or {}, new_data)

            if diff:
                print(f"[*] {name} 内容发生变化！")
                files_to_update.append((name, new_data))
                differences.append((name, diff, old_data, new_data))
                has_content_changed = True
            else:
                print(f"[INFO] {name} 内容未发生实质性变化。")
                differences.append((name, None, old_data, new_data))

        generate_changes_report(differences)

        if not has_content_changed:
            print("[INFO] 所有文件均无实质变化，无需提交。")
            # 即使内容没变，URL也可能变了，所以依然要保存缓存
            save_cache(x19_url, g79_url, new_x19_hash, new_g79_hash)
            return

        # --- 更新 GitHub 文件 ---
        for filename, data in files_to_update:
            content = json.dumps(data, ensure_ascii=False, indent=4)
            update_github_file(
                owner=GITHUB_OWNER, repo=GITHUB_REPO, filepath=filename, content=content,
                token=GITHUB_TOKEN, branch=GITHUB_BRANCH, commit_msg=f"🔄 Update {filename} (content changed)"
            )
            with open(filename, "w", encoding="utf-8") as f: f.write(content)
        
        for report_file in [CHANGELOG_MD, CHANGELOG_JSON]:
            if os.path.exists(report_file):
                with open(report_file, "r", encoding="utf-8") as f:
                    report_content = f.read()
                update_github_file(
                    owner=GITHUB_OWNER, repo=GITHUB_REPO, filepath=report_file, content=report_content,
                    token=GITHUB_TOKEN, branch=GITHUB_BRANCH, commit_msg=f"📄 Update changelog for {datetime.now().strftime('%Y-%m-%d')}"
                )

        print("\n🎉 所有变更文件已成功更新！")
        save_cache(x19_url, g79_url, new_x19_hash, new_g79_hash)

    except Exception as e:
        import traceback
        traceback.print_exc()
        print(f"\n[CRITICAL] 执行失败: {e}")
        exit(1)

if __name__ == "__main__":
    main()
