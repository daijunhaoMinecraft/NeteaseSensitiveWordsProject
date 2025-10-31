# update_script.py
# 功能：自动解密、对比、更新网易敏感词，并生成变化报告
# 用途：配合 GitHub Actions 自动化运行

import re
import json
import base64
import requests
from Crypto.Cipher import ARC4
import os
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
    # 排序键以确保哈希的稳定性
    sorted_data = json.dumps(data, sort_keys=True, ensure_ascii=False, separators=(',', ':'))
    return md5(sorted_data.encode('utf-8')).hexdigest()

# 【修复】重构对比函数，使其能处理所有 regex 子类别
def compare_data_by_content(old_data, new_data):
    """
    通过比较正则表达式的内容而不是不稳定的ID来找出所有类别的差异。
    这个函数现在是唯一的对比引擎。
    """
    # 检查哈希值，如果哈希相同，则内容完全相同，直接返回
    if hash_json(old_data) == hash_json(new_data):
        return None

    all_changes = {}

    old_regex_root = old_data.get("regex", {})
    new_regex_root = new_data.get("regex", {})

    # 获取所有需要对比的类别（例如 nickname, shield, all 等）
    all_categories = set(old_regex_root.keys()) | set(new_regex_root.keys())

    for category in sorted(list(all_categories)):
        old_dict = old_regex_root.get(category, {})
        new_dict = new_regex_root.get(category, {})

        # 确保我们处理的是字典
        if not isinstance(old_dict, dict) or not isinstance(new_dict, dict):
            continue

        # 创建从 regex 内容到 ID 的反向映射
        old_content_to_id = {v: k for k, v in old_dict.items()}
        new_content_to_id = {v: k for k, v in new_dict.items()}

        old_contents = set(old_content_to_id.keys())
        new_contents = set(new_content_to_id.keys())

        added_contents = new_contents - old_contents
        removed_contents = old_contents - new_contents
        
        category_changes = {}
        if added_contents:
            category_changes["added"] = sorted(
                [{"id": new_content_to_id[c], "value": c} for c in added_contents],
                key=lambda x: str(x['id'])
            )
        if removed_contents:
            category_changes["removed"] = sorted(
                [{"id": old_content_to_id[c], "value": c} for c in removed_contents],
                key=lambda x: str(x['id'])
            )
        
        if category_changes:
            all_changes[category] = category_changes

    return all_changes if all_changes else None


# 【修复】更新报告生成函数以适应新的差异结构
def generate_and_save_report(differences):
    """
    根据差异生成报告。只有在有实际变化时才写入文件。
    :param differences: [(filename, diff_dict), ...]
    :return: (bool) 是否生成了新报告
    """
    if not any(d[1] for d in differences):
        print("[INFO] 未检测到任何内容变化，跳过生成报告。")
        return False

    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    md_content = f"# 📝 敏感词更新报告 - {timestamp}\n\n"
    md_content += "本次检测到以下文件发生变化：\n\n"
    json_changes = []

    for filename, diff_dict in differences:
        if not diff_dict: continue

        md_content += f"## 📄 `{filename}`\n\n"
        json_changes.append({"file": filename, "diff": diff_dict})

        for category, changes in sorted(diff_dict.items()):
            md_content += f"### 类别: `{category}`\n\n"
            
            added = changes.get("added", [])
            if added:
                md_content += "#### ➕ 新增规则\n"
                for item in added:
                    md_content += f"- **ID `{item['id']}`**: `{item['value'][:200]}`\n"
                md_content += "\n"

            removed = changes.get("removed", [])
            if removed:
                md_content += "#### ❌ 删除规则\n"
                for item in removed:
                    md_content += f"- **ID `{item['id']}`**: `{item['value'][:200]}`\n"
                md_content += "\n"

    print(f"[INFO] 检测到变化，正在生成报告文件：{CHANGELOG_MD} 和 {CHANGELOG_JSON}")
    with open(CHANGELOG_MD, "w", encoding="utf-8") as f:
        f.write(md_content)
    with open(CHANGELOG_JSON, "w", encoding="utf-8") as f:
        json.dump(json_changes, f, ensure_ascii=False, indent=4)
    
    return True

# ========== 主函数 ==========

def main():
    print("[+] 开始更新敏感词数据...")
    
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
        g79_url = get_url("android_g79")
        
        if x19_url == cache.get("x19_url") and g79_url == cache.get("g79_url"):
            print("[INFO] URLs 未变化，无需更新。")
            return

        print("[*] URLs 发生变化，准备下载新内容...")
        x19_data = decrypt_content(session.get(x19_url, verify=False).content, "c42bf7f39d479999")
        g79_data = decrypt_content(session.get(g79_url, verify=False).content, "c42bf7f39d476db3")

        new_x19_hash = hash_json(x19_data)
        new_g79_hash = hash_json(g79_data)

        # --- 对比内容 ---
        has_content_changed = False
        all_data_to_check = [
            ("X19SensitiveWords.json", x19_data, new_x19_hash),
            ("G79SensitiveWords.json", g79_data, new_g79_hash),
        ]

        for name, new_data, new_hash in all_data_to_check:
            old_data = {}
            if os.path.exists(name):
                try:
                    with open(name, "r", encoding="utf-8") as f:
                        old_data = json.load(f)
                except Exception as e:
                    print(f"[WARN] 无法读取旧文件 {name}: {e}")
            
            # 【核心变更】使用新的对比函数
            diff = compare_data_by_content(old_data, new_data)

            if diff:
                print(f"[*] {name} 内容发生变化！")
                files_to_update.append((name, new_data))
                differences.append((name, diff))
                has_content_changed = True
            else:
                print(f"[INFO] {name} 内容未发生实质性变化。")

        # --- 根据是否有变化来生成报告并更新文件 ---
        if has_content_changed:
            generate_and_save_report(differences)

            # 更新敏感词文件
            for filename, data in files_to_update:
                content = json.dumps(data, ensure_ascii=False, indent=4)
                with open(filename, "w", encoding="utf-8") as f:
                    f.write(content)
            
            # 保存新状态
            save_cache(x19_url, g79_url, new_x19_hash, new_g79_hash)
            print("\n🎉 脚本执行完毕，检测到内容更新。")
        else:
            print("[INFO] 所有文件均无实质变化，无需更新文件或报告。")
            save_cache(x19_url, g79_url, new_x19_hash, new_g79_hash)

    except Exception as e:
        import traceback
        traceback.print_exc()
        print(f"\n[CRITICAL] 执行失败: {e}")
        exit(1)

if __name__ == "__main__":
    main()
