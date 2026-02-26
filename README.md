# VulSentinel

离线流水线：读取 `nuclei-templates/` CVE 模板，调用 OpenAI 兼容接口生成每个 CVE 的 Markdown 分析报告，为下游漏洞修复决策提供结构化 POC 分析依据。

## 运行前置

- Python 3
- 安装依赖：

```bash
python3 -m pip install -r requirements.txt
```

- 在仓库根目录提供 `.env`（已被 `.gitignore` 忽略）：

```bash
OPENAI_BASE_URL=http(s)://host:port/v1
OPENAI_API_KEY=...
OPENAI_MODEL=...
VULSENTINEL_CONCURRENCY=4
```

- `OPENAI_BASE_URL` 必须包含 `/v1`
- `OPENAI_API_KEY` 不会出现在日志中
- `VULSENTINEL_CONCURRENCY` 可选，范围 `[1, 16]`，默认 4

## 用法

```bash
# 最小运行
python3 cve_poc_llm_reports_cli.py

# 仅处理 2025 年及之后的 CVE
python3 cve_poc_llm_reports_cli.py --from-year 2025
```

幂等：若报告文件已存在则跳过，不重复调用模型。

## 并发

默认 4 并发处理 LLM 调用，通过 `.env` 中的 `VULSENTINEL_CONCURRENCY` 调整（范围 `[1, 16]`）。

## 输出

报告路径：`reports/<prefix>/cves/<year>/<CVE-ID>.md`

每份报告包含 YAML frontmatter，提供结构化信号供下游解析：

```yaml
---
cve_id: CVE-2026-21858
template_path: nuclei-templates/http/cves/2026/CVE-2026-21858.yaml
affected_product: n8n
severity: critical
authentication: none
external_callback: false
affected_versions: ">= 1.65.0, < 1.121.0"
preconditions: []
poc_classification: rce
---
```

| 字段 | 说明 |
|------|------|
| `affected_product` | 受影响的软件产品名 |
| `severity` | 漏洞严重程度 |
| `authentication` | 利用是否需要认证（none / required / optional） |
| `external_callback` | 利用是否需要攻击者接收带外回调（DNS/HTTP） |
| `affected_versions` | 受影响版本范围（仅模板强制检测的范围） |
| `preconditions` | 除版本外的利用前置条件 |
| `poc_classification` | 漏洞能力分类（rce / info-leak / auth-bypass / state-change / dos / detect-only） |

信号字段从 LLM 输出自动提取；提取失败时 frontmatter 仅保留 `cve_id` 和 `template_path`。

索引：`reports/cves.jsonl`，每行 `{"ID": "...", "report_path": "..."}`，仅追加本次新生成的报告。

## 退出码

| 退出码 | 含义 |
|--------|------|
| 0 | 全部成功或全部跳过 |
| 1 | 存在失败的 CVE |
| 2 | 配置错误 |

## 测试

```bash
python3 -m pytest tests/ -v
```

## CI/CD

GitHub Actions 自动化：

- **测试**：每次 push / PR 自动运行 `pytest`
- **每日报告生成**：每天 02:00 UTC 自动拉取最新 `nuclei-templates`，生成新增 CVE 报告并提交

需在仓库 Settings → Secrets 中配置：`OPENAI_BASE_URL`、`OPENAI_API_KEY`、`OPENAI_MODEL`。
