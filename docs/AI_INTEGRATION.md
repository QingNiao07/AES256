# AI 集成说明（AI INTEGRATION）

本工具箱接入 **DeepSeek V4.1 Flash**（`model=deepseek-flash`），为加密操作提供
离线优先的智能助手。

## 默认离线

`DeepSeekClient` 默认 `offline=True`：

- 未显式勾选「允许联网」时，所有请求在本地被拦截，不产生任何网络流量。
- 用户可在 AI 面板中开启联网；开关状态写入配置并记入审计。

## 配置

```python
DeepSeekClient(
    model="deepseek-flash",
    base_url="https://api.deepseek.com",   # OpenAI 兼容
    offline=True,
    timeout=(10, 180),                       # connect, read
    max_retry=2,                             # 指数退避，1.6^attempt
)
```

- API Key 由**主密钥派生子密钥加密**后存于 `aes_log/ai_secret.bin`。
- 思考模式：`thinking={"type": "enabled"|"disabled"}`，`reasoning_effort="high"|"max"`。
- 上下文 1M tokens，单次最大输出 384K。

## 出网脱敏（sanitize）

请求发出前经 `app/services/ai/sanitize.py` 处理：

1. 绝对路径 → `<PATH>`；
2. 文件名 → `<FILE>`；
3. 密文块 / hex 串 → `<BLOB>`；
4. 用户主目录用户名 → `<USER>`。

仅发送脱敏后的自然语言问题，绝不发送文件内容或密文。

## 审计

- 对话**内容不写入** `operation.log`；
- 仅在 `ai_audit.log` 记录元数据：时间、模型、token 用量、是否脱敏命中、缓存命中。

## 隐私建议

- 处理高度敏感数据时保持离线模式；
- 联网前确认已理解脱敏范围（如上下文中的专有名词不会被自动脱敏）。

## 适配新供应商

在 `app/services/ai/client.py` 增加一个适配器，实现
`chat(messages, **kw) -> str`，复用同一套离线闸门与脱敏管线即可。
