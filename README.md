# VulSentinel

读取 [nuclei-templates](https://github.com/projectdiscovery/nuclei-templates) CVE 模板 → LLM 分析 → 输出结构化 Markdown 报告，供下游漏洞修复决策。

## 快速开始

```bash
pip install -r requirements.txt
```

`.env`：

```
OPENAI_BASE_URL=https://host/v1
OPENAI_API_KEY=sk-xxx
OPENAI_MODEL=gpt-4o
VULSENTINEL_CONCURRENCY=4   # 可选，默认 4
```

运行：

```bash
python3 vulsentinel_cli.py --from-year 2026
python3 vulsentinel_cli.py --from-year 2026 --limit 10
```

幂等，已有报告自动跳过。

## 报告格式

`reports/<prefix>/cves/<year>/<CVE-ID>.md`

```yaml
---
cve_id: CVE-2026-21859
template_path: nuclei-templates/http/cves/2026/CVE-2026-21859.yaml
affected_product: Mailpit
severity: high
authentication: none
external_callback: false
affected_versions: < 1.24.0
preconditions: []
poc_classification: info-leak
---
```

| 字段 | 说明 |
|------|------|
| `affected_product` | 受影响产品 |
| `severity` | 严重程度 |
| `authentication` | none / required / optional |
| `external_callback` | 是否需要带外回调 |
| `affected_versions` | 受影响版本范围 |
| `preconditions` | 利用前置条件 |
| `poc_classification` | info-leak / auth-bypass / rce / state-change / dos / detect-only |
