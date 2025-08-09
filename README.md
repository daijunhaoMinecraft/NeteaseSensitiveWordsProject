# 敏感词过滤服务

一个基于 C++ 开发的高性能敏感词过滤 HTTP 服务，支持多PC敏感词检测(X19)和PE敏感词检测(G79)，每小时自动更新，词库来源于网易我的世界，解密来源于EnvSDKLib

## 功能特性

- 🎯 **多游戏支持**: 支持 g79 和 x19 两个游戏的敏感词过滤
- 🔄 **实时更新**: 每小时自动从远程服务器更新敏感词规则
- 🛡️ **多种过滤策略**: 支持拦截 (intercept)、屏蔽 (shield)、替换 (replace) 等多种处理方式
- 👤 **昵称检测**: 专门的昵称敏感词检测接口
- 🔒 **安全加密**: 使用 RC4 加密算法解密远程配置
- ⚡ **高性能**: 基于 PCRE2 正则表达式引擎，处理速度快
- 🌐 **RESTful API**: 提供标准的 HTTP JSON API

## 技术栈

- **语言**: C++
- **HTTP 服务**: cpp-httplib
- **JSON 处理**: nlohmann/json
- **正则表达式**: PCRE2
- **加密**: RC4 算法
- **SSL/TLS**: OpenSSL

## 编译依赖

```bash
# Ubuntu/Debian
sudo apt-get install libpcre2-dev libssl-dev nlohmann-json3-dev

# CentOS/RHEL
sudo yum install pcre2-devel openssl-devel

# macOS (使用 Homebrew)
brew install pcre2 openssl nlohmann-json
```

## 编译方法

```bash
# 克隆项目
git clone <repository-url>
cd sensitive-word-filter

# 编译
g++ -std=c++17 -O2 \
    -DCPPHTTPLIB_OPENSSL_SUPPORT \
    -I/usr/include/pcre2 \
    -o sensitive_word_filter main.cpp \
    -lpcre2-8 -lssl -lcrypto -lpthread
```

## 运行

```bash
./sensitive_word_filter
```

服务将在 `http://0.0.0.0:8143` 启动。

## API 接口

### 1. 健康检查

**GET** `/`

返回: `Hello World!`

### 2. G79 游戏敏感词检测

**POST** `/g79/review/words`

请求参数:
```json
{
    "level": "0",
    "channel": "item_comment",
    "word": "要检测的文本内容"
}
```

响应:
```json
{
    "code": 0,
    "message": "pass",
    "regularIdList": {
        "Shield": [],
        "Intercept": [],
        "Replace": []
    },
    "ReplaceContent": "处理后的内容",
    "OriginalContent": "原始内容"
}
```

### 3. G79 游戏昵称检测

**POST** `/g79/review/nickname`

请求参数:
```json
{
    "nickname": "要检测的昵称"
}
```

响应:
```json
{
    "code": 0,
    "message": "pass",
    "NickNameRegularId": [],
    "OriginalNickName": "原始昵称",
    "ReplaceNickName": "处理后的昵称"
}
```

### 4. X19 游戏接口

类似于 G79，但路径前缀为 `/x19/`：
- **POST** `/x19/review/words`
- **POST** `/x19/review/nickname`

## 返回码说明

| 返回码 | 说明 |
|--------|------|
| 0 | 通过检测 |
| 1 | 检测到敏感词 |
| 500 | 服务器内部错误 |

## 过滤策略

1. **Shield (屏蔽)**: 将敏感词替换为 `*` 号
2. **Intercept (拦截)**: 检测到敏感词时拦截，同样替换为 `*` 号
3. **Replace (替换)**: 替换敏感词为 `*` 号
4. **Nickname (昵称)**: 专门用于昵称检测的规则

## 配置说明

服务会自动从以下地址获取敏感词配置：
- 初始化地址: `http://optsdk.gameyw.netease.com/initbox_{gameid}.html`
- 配置文件会使用 RC4 算法加密

### 加密密钥

- G79(网易我的世界PE客户端): `c42bf7f39d476db3`
- X19(网易我的世界PC客户端): `c42bf7f39d479999`

## 自动更新

服务启动后会每小时自动更新一次敏感词规则，确保过滤规则的时效性。

## 使用示例

### curl 测试

```bash
# 测试 G79 敏感词检测
curl -X POST http://localhost:8143/g79/review/words \
  -H "Content-Type: application/json" \
  -d '{
    "level": "0",
    "channel": "item_comment", 
    "word": "测试文本"
  }'

# 测试昵称检测
curl -X POST http://localhost:8143/g79/review/nickname \
  -H "Content-Type: application/json" \
  -d '{
    "nickname": "测试昵称"
  }'
```

### Python 示例

```python
import requests
import json

url = "http://localhost:8143/g79/review/words"
data = {
    "level": "0",
    "channel": "item_comment",
    "word": "要检测的文本"
}

response = requests.post(url, json=data)
result = response.json()
print(json.dumps(result, indent=2, ensure_ascii=False))
```

## 日志说明

服务运行时会输出以下日志：
- 初始化完成: `init_sensitive_word OK for game: {gameid}`
- 规则更新: `Refresh Sensitive words` / `Refresh Done!`
- 错误信息: 各种错误场景的详细信息

## 性能特性

- 使用 PCRE2 高性能正则表达式引擎
- 多线程支持，主服务与更新任务分离
- 内存中缓存编译后的正则表达式
- 递归处理确保所有敏感词都被替换

## 注意事项

1. 服务依赖网络连接来获取最新的敏感词规则
2. 首次启动时需要网络连接来下载配置
3. 如果网络连接失败，服务仍可使用已缓存的规则运行
4. 建议在生产环境中配置适当的防火墙规则

## 许可证

本项目采用 MIT 许可证。

## 贡献

欢迎提交 Issue 和 Pull Request 来改进这个项目。
