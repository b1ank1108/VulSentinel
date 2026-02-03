# VulSentinel

本仓库包含一条离线流水线：读取本仓库内的 `nuclei-templates/` CVE 模板集合，调用 OpenAI 兼容 Chat 接口生成每个 CVE 的结构化报告（JSON），并维护索引（JSONL）。

## 运行前置

- Python 3（本仓库目前用 `python3` 直接运行脚本）
- 安装依赖：

```bash
python3 -m pip install -r requirements.txt
```

- 一个可用的 OpenAI 兼容服务（或网关），并在仓库根目录提供 `.env`（已被 `.gitignore` 忽略）：

```bash
OPENAI_BASE_URL=http(s)://host:port/v1
OPENAI_API_KEY=...
OPENAI_MODEL=...
```

注意：

- `OPENAI_BASE_URL` 必须包含 `/v1`；程序不会校验/自动补 `/v1`，也不会自动修正格式。
- 日志/报错不会输出明文 `OPENAI_API_KEY`。

说明：

- 只读 `nuclei-templates/`，不会修改其内容
- 输出只写入 `reports/`（或你指定的 `--reports-dir`）

## 用法

最小运行：

```bash
python3 cve_poc_llm_reports_cli.py
```

按年份增量（仅处理 `CVE-YYYY-*` 中 `YYYY >= from_year` 的条目）：

```bash
python3 cve_poc_llm_reports_cli.py --from-year 2025
```

幂等跳过：

- 若目标报告文件已存在（`report_path` 存在），则该 CVE 会被跳过（`event=skip reason="report_exists"`），且不会重复调用模型、不会重复追加索引。

## 输出

单个 CVE 报告（示例）：

- `reports/<prefix>/cves/<year>/<ID>.json`

索引（仅对“本次成功生成的新报告”追加写）：

- `reports/cves.jsonl`：每行至少包含 `{ "ID": "...", "report_path": "reports/..." }`

其中：

- `<prefix>` 来自 `file_path` 中 `/cves/` 之前的前缀（例如 `http` / `javascript` / `network`）
- `<year>` 必须来自 `ID` 解析出来的年份（不依赖 `file_path` 中的年份目录）

## 最小自检

见 `docs/cve_poc_llm_reports_selfcheck.md`（包含两条可复制的“生成 / 幂等跳过”命令）。
