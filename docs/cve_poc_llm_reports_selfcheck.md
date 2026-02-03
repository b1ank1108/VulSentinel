# cve_poc_llm_reports 最小自检（生成 / 跳过）

前置：

- 安装依赖：`python3 -m pip install -r requirements.txt`
- 需要一个可用的 OpenAI 兼容服务（或网关），并在仓库根目录创建 `.env`（`OPENAI_BASE_URL` 必须包含 `/v1`，程序不做校验/自动修正）：

```bash
OPENAI_BASE_URL=http(s)://host:port/v1
OPENAI_API_KEY=...
OPENAI_MODEL=...
```

## 1) 生成（示例：CVE-2021-44228 + CVE-2025-49844）

```bash
TMP=/tmp/cplr-selfcheck
rm -rf "$TMP"
mkdir -p "$TMP/nuclei-templates"

rg '"ID":"CVE-2021-44228"|"ID":"CVE-2025-49844"' nuclei-templates/cves.json > "$TMP/nuclei-templates/cves.json"

mkdir -p "$TMP/nuclei-templates/http/cves/2021" "$TMP/nuclei-templates/javascript/cves/2025"
cp nuclei-templates/http/cves/2021/CVE-2021-44228.yaml "$TMP/nuclei-templates/http/cves/2021/"
cp nuclei-templates/javascript/cves/2025/CVE-2025-49844.yaml "$TMP/nuclei-templates/javascript/cves/2025/"

python3 cve_poc_llm_reports_cli.py \\
  --templates-dir "$TMP/nuclei-templates" \\
  --reports-dir "$TMP/reports"
```

期望结果（成功时）：

- 生成报告：
  - `$TMP/reports/http/cves/2021/CVE-2021-44228.json`
  - `$TMP/reports/javascript/cves/2025/CVE-2025-49844.json`
- 生成索引：`$TMP/reports/cves.jsonl`（至少 2 行）

## 2) 跳过（幂等：report 已存在则跳过）

再次运行同一条命令：

```bash
python3 cve_poc_llm_reports_cli.py \\
  --templates-dir "$TMP/nuclei-templates" \\
  --reports-dir "$TMP/reports"
```

期望结果：

- 日志中出现 `event=skip` 且 `reason="report_exists"`
- `$TMP/reports/cves.jsonl` 行数不变（不重复追加）
