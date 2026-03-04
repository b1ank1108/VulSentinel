# VulSentinel

读取 [nuclei-templates](https://github.com/projectdiscovery/nuclei-templates) CVE 模板 → LLM 分析 → 输出结构化 Markdown 报告，供下游漏洞修复决策。

[![Reports](https://img.shields.io/badge/CVE_Reports-3900+-blue)](reports/cves.jsonl)
[![Last Update](https://img.shields.io/badge/Last_Update-2026--03--04-green)](https://github.com/b1ank1108/VulSentinel/commits/main)

## 项目特点

- **自动化分析**：基于 nuclei-templates 的 CVE 模板，使用 LLM 进行深度分析
- **结构化输出**：统一的 YAML frontmatter + Markdown 格式，便于程序化处理
- **幂等执行**：已生成的报告自动跳过，支持增量更新
- **并发处理**：可配置并发数，提升大批量分析效率
- **持续更新**：通过 GitHub Actions 自动跟踪最新 CVE

## 快速开始

### 安装依赖

```bash
pip install -r requirements.txt
```

### 配置环境变量

创建 `.env` 文件：

```env
OPENAI_BASE_URL=https://host/v1
OPENAI_API_KEY=sk-xxx
OPENAI_MODEL=gpt-4o
VULSENTINEL_CONCURRENCY=4   # 可选，默认 4
```

### 运行分析

```bash
# 分析指定年份及之后的所有 CVE
python3 vulsentinel_cli.py --from-year 2026

# 限制分析数量（用于测试）
python3 vulsentinel_cli.py --from-year 2026 --limit 10
```

程序会自动跳过已生成的报告，支持增量更新。

## 报告格式

### 目录结构

```
reports/<prefix>/cves/<year>/<CVE-ID>.md
```

例如：`reports/http/cves/2026/CVE-2026-21859.md`

### 报告内容

每个报告包含 YAML frontmatter 和详细分析：

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

### 字段说明

| 字段 | 说明 | 可选值 |
|------|------|--------|
| `affected_product` | 受影响产品名称 | - |
| `severity` | 严重程度 | critical / high / medium / low / info |
| `authentication` | 认证要求 | none / required / optional |
| `external_callback` | 是否需要带外回调（如 DNS/HTTP） | true / false |
| `affected_versions` | 受影响版本范围 | - |
| `preconditions` | 利用前置条件列表 | - |
| `poc_classification` | PoC 类型分类 | info-leak / auth-bypass / rce / state-change / dos / detect-only |

## 数据统计

- **总报告数**：3900+ CVE
- **覆盖年份**：2000-2026
- **数据源**：[nuclei-templates](https://github.com/projectdiscovery/nuclei-templates)
- **更新频率**：自动跟踪上游更新

## 技术架构

- **模板解析**：读取 nuclei YAML 模板，提取 CVE 信息和 PoC 逻辑
- **LLM 分析**：使用 OpenAI API 进行深度分析，生成结构化输出
- **并发处理**：基于 asyncio 的异步并发，可配置并发数
- **幂等设计**：基于文件系统的去重，避免重复分析

## License

MIT
