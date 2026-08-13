#!/usr/bin/env bash
# 检查本框架的本地依赖与 OpenCode 配置。
# 除 --python 使用临时目录外，脚本不会修改文件。

set -u
set -o pipefail

run_tests=false
check_python=false
check_mcp=true
failures=0
warnings=0

usage() {
  cat <<'EOF'
用法: ./initial.sh [选项]

检查本地工具、项目/全局 OpenCode 配置及 Coverage Ledger MCP 健康状态。
当扫描器为 auto 模式时，OpenGrep 与 Semgrep 二选一即可，优先使用 OpenGrep。

选项:
  --python          运行临时 Joern Python 前端冒烟检查。
  --test            环境检查后运行完整项目回归测试。
  --no-mcp          跳过 Coverage Ledger MCP 健康检查；仍直接检查扫描器和 Joern CLI。
  -h, --help        显示本帮助。

项目配置默认为 .opencode/opencode.json。若需检查其他配置，运行前设置
OPENCODE_CONFIG。

结果说明： 【通过】表示可用， 【警告】表示可选能力缺失， 【失败】表示所选
审计流程被阻断，需解决问题后才能运行。
EOF
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --python) check_python=true ;;
    --test) run_tests=true ;;
    --no-mcp) check_mcp=false ;;
    -h|--help) usage; exit 0 ;;
    *)
      printf '【失败】未知选项: %s\n' "$1" >&2
      usage >&2
      exit 2
      ;;
  esac
  shift
done

script_dir="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$script_dir"

pass() {
  printf '【通过】%s\n' "$1"
}

info() {
  printf '【提示】%s\n' "$1"
}

warn() {
  warnings=$((warnings + 1))
  printf '【警告】%s\n' "$1"
}

fail() {
  failures=$((failures + 1))
  printf '【失败】%s\n' "$1"
}

resolve_executable() {
  candidate="$1"
  if [ -z "$candidate" ]; then
    return 1
  fi
  if [ -x "$candidate" ]; then
    printf '%s\n' "$candidate"
    return 0
  fi
  command -v "$candidate" 2>/dev/null
}

probe_executable() {
  label="$1"
  candidate="$2"
  if executable="$(resolve_executable "$candidate")"; then
    version="$($executable --version 2>&1 | sed -n '1p' || true)"
    if [ -n "$version" ]; then
      pass "$label: $version"
    else
      pass "$label 可用"
    fi
    return 0
  fi
  return 1
}

probe_available() {
  label="$1"
  candidate="$2"
  if resolve_executable "$candidate" >/dev/null; then
    pass "$label 可用"
    return 0
  fi
  return 1
}

check_configs() {
  node - "$project_config" "$template_config" "$global_config" <<'NODE'
const fs = require("fs");
const path = require("path");

const [projectPath, templatePath, globalPath] = process.argv.slice(2);
let invalid = false;

function readJson(label, file, required) {
  if (!fs.existsSync(file)) {
    console.log(required ? `  - ${label}: 缺失` : `  - ${label}: 未配置`);
    if (required) invalid = true;
    return null;
  }
  try {
    const value = JSON.parse(fs.readFileSync(file, "utf8"));
    console.log(`  - ${label}: JSON 有效`);
    return value;
  } catch (error) {
    console.log(`  - ${label}: JSON 无效（${error.message}）`);
    invalid = true;
    return null;
  }
}

const project = readJson("项目 opencode.json", projectPath, true);
const template = readJson("项目模板", templatePath, true);
const global = readJson("全局 opencode.json", globalPath, false);

if (template && !template.default_agent) {
  console.log("  - 项目模板: 缺少 default_agent");
  invalid = true;
}

if (project) {
  if (!project.default_agent || typeof project.default_agent !== "string") {
    console.log("  - 项目 opencode.json: 缺少 default_agent");
    invalid = true;
  }
  const requiredLocal = ["coverage_ledger"];
  for (const name of requiredLocal) {
    const server = project.mcp?.[name];
    if (!server || server.enabled === false || server.type !== "local" || !Array.isArray(server.command)) {
      console.log(`  - 项目 MCP ${name}: 缺失、已禁用或不是本地服务`);
      invalid = true;
      continue;
    }
    const script = server.command.find(value => typeof value === "string" && value.endsWith(".mjs"));
    if (script && !fs.existsSync(path.resolve(process.cwd(), script))) {
      console.log(`  - 项目 MCP ${name}: 启动脚本缺失`);
      invalid = true;
    }
  }
}

const projectMcp = new Set(Object.keys(project?.mcp ?? {}));
const globalMcp = new Set(Object.keys(global?.mcp ?? {}));
const duplicates = [...projectMcp].filter(name => globalMcp.has(name));
if (duplicates.length > 0) console.log(`  - 警告: 项目与全局 MCP 重名: ${duplicates.join(", ")}`);
else console.log("  - 项目与全局 MCP: 无重名项");

console.log("  - finding 真实性复核: 使用项目内本地正方/反方/Moderator 链，无需外部 review MCP");
console.log("  - 提示: 项目专用 MCP 保留在项目配置中，只有共享服务才配置到全局");

process.exit(invalid ? 1 : 0);
NODE
}

check_mcp_health() {
  node --input-type=module - "$project_config" <<'NODE'
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { Client } from "./.opencode/node_modules/@modelcontextprotocol/sdk/dist/esm/client/index.js";
import { StdioClientTransport } from "./.opencode/node_modules/@modelcontextprotocol/sdk/dist/esm/client/stdio.js";

const configPath = process.argv[2];
const config = JSON.parse(await readFile(configPath, "utf8"));
const probes = [
  { name: "coverage_ledger", requiredTools: ["coverage_get_packet", "coverage_finalize"] },
  { name: "chrome-devtools", requiredTools: ["list_pages", "new_page", "evaluate_script", "take_snapshot", "take_screenshot"] },
];
let failed = false;

for (const probe of probes) {
  const settings = config.mcp?.[probe.name];
  if (!settings?.enabled || !Array.isArray(settings.command) || settings.command.length === 0) {
    console.log(`【失败】MCP ${probe.name}: 项目配置中未启用`);
    failed = true;
    continue;
  }
  const [command, ...args] = settings.command;
  const client = new Client({ name: "initial-check", version: "1.0.0" });
  try {
    const transport = new StdioClientTransport({
      command,
      args,
      cwd: resolve(settings.cwd ?? "."),
      env: { ...process.env, ...(settings.environment ?? {}) },
    });
    await client.connect(transport);
    const listed = await client.listTools();
    const tools = new Set(listed.tools.map(tool => tool.name));
    if (probe.requiredTools && probe.requiredTools.some(name => !tools.has(name))) {
      throw new Error(`缺少必需工具: ${probe.requiredTools.filter(name => !tools.has(name)).join(", ")}`);
    }
    if (probe.health) {
      const result = await client.callTool({ name: probe.health, arguments: {} });
      const raw = result.content?.find(item => item.type === "text")?.text ?? "{}";
      const health = JSON.parse(raw);
      if (health.healthy !== true) throw new Error(JSON.stringify(health.checks ?? health.engines ?? health));
    }
    console.log(`【通过】MCP ${probe.name}: 健康`);
  } catch (error) {
    console.log(`【失败】MCP ${probe.name}: ${error.message}`);
    failed = true;
  } finally {
    await client.close().catch(() => undefined);
  }
}

process.exit(failed ? 1 : 0);
NODE
}

project_config="${OPENCODE_CONFIG:-.opencode/opencode.json}"
template_config=".opencode/opencode.json.bak"
global_config="${XDG_CONFIG_HOME:-$HOME/.config}/opencode/opencode.json"

printf 'OpenCode 框架初始化检查\n\n'

if probe_executable "Git" "git"; then :; else fail "Git 不可用"; fi

node_ok=false
if probe_executable "Node.js" "node"; then
  node_major="$(node -p 'process.versions.node.split(".")[0]' 2>/dev/null || printf '0')"
  if [ "$node_major" -ge 20 ] 2>/dev/null; then
    node_ok=true
  else
    fail "需要 Node.js 20 或更高版本"
  fi
else
  fail "Node.js 不可用"
fi

if probe_executable "npm" "npm"; then :; else fail "npm 不可用"; fi
if probe_executable "OpenCode" "opencode"; then :; else fail "OpenCode CLI 不可用"; fi

config_ok=false
if [ "$node_ok" = true ]; then
  printf '\nOpenCode 配置\n'
  if check_configs; then
    pass "OpenCode 配置契约"
    config_ok=true
  else
    fail "OpenCode 配置契约"
  fi
else
  fail "缺少 Node.js，无法校验 OpenCode JSON"
fi

printf '\n项目依赖\n'
if [ -d .opencode/node_modules/@modelcontextprotocol/sdk ] && npm --prefix .opencode ls --omit=dev --depth=0 >/dev/null 2>&1; then
  pass "项目 Node.js 依赖"
  dependencies_ok=true
else
  fail "项目依赖不完整；请运行 npm ci --prefix .opencode"
  dependencies_ok=false
fi

if [ "$config_ok" = true ]; then
  printf '\n静态扫描器与 Joern 工具\n'
  opengrep_bin="${OPENGREP_BIN:-opengrep}"
  semgrep_bin="${SEMGREP_BIN:-semgrep}"
  semgrep_engine="${SEMGREP_ENGINE:-auto}"

  opengrep_ok=false
  semgrep_ok=false
  opengrep_version=""
  semgrep_version=""
  if opengrep_path="$(resolve_executable "$opengrep_bin")"; then
    opengrep_ok=true
    opengrep_version="$($opengrep_path --version 2>&1 | sed -n '1p' || true)"
  fi
  if semgrep_path="$(resolve_executable "$semgrep_bin")"; then
    semgrep_ok=true
    semgrep_version="$($semgrep_path --version 2>&1 | sed -n '1p' || true)"
  fi

  case "$semgrep_engine" in
    auto)
      if [ "$opengrep_ok" = false ] && [ "$semgrep_ok" = false ]; then
        fail "静态扫描器（OpenGrep / Semgrep）均不可用；请安装其中任意一个"
      elif [ "$opengrep_ok" = true ] && [ "$semgrep_ok" = true ]; then
        pass "静态扫描器（OpenGrep / Semgrep，二选一即可）：均可用；auto 模式优先 OpenGrep"
      elif [ "$opengrep_ok" = true ]; then
        pass "静态扫描器（OpenGrep / Semgrep，二选一即可）：OpenGrep ${opengrep_version:-可用}"
        info "Semgrep 未安装；OpenGrep 可用时无需处理"
      else
        pass "静态扫描器（OpenGrep / Semgrep，二选一即可）：Semgrep ${semgrep_version:-可用}"
        info "OpenGrep 未安装；Semgrep 可用时无需处理"
      fi
      ;;
    opengrep)
      if [ "$opengrep_ok" = false ]; then
        fail "SEMGREP_ENGINE=opengrep，因此静态扫描器必须使用 OpenGrep"
      else
        pass "静态扫描器：OpenGrep ${opengrep_version:-可用}"
      fi
      ;;
    semgrep)
      if [ "$semgrep_ok" = false ]; then
        fail "SEMGREP_ENGINE=semgrep，因此静态扫描器必须使用 Semgrep"
      else
        pass "静态扫描器：Semgrep ${semgrep_version:-可用}"
      fi
      ;;
    *) fail "SEMGREP_ENGINE 必须是 auto、opengrep 或 semgrep" ;;
  esac

  joern_bin="${JOERN_BIN:-joern}"
  joern_parse_bin="${JOERN_PARSE_BIN:-joern-parse}"
  joern_java_bin="${JOERN_JAVA_BIN:-}"
  joern_gnubin="${JOERN_GNUBIN:-}"
  joern_parse_path=""

  if probe_available "Joern" "$joern_bin"; then :; else fail "Joern 不可用"; fi
  if joern_parse_path="$(resolve_executable "$joern_parse_bin")"; then
    if probe_available "joern-parse" "$joern_parse_bin"; then :; fi
  else
    fail "joern-parse 不可用"
  fi

  if [ -n "$joern_java_bin" ]; then
    if probe_executable "Joern 所用 Java" "$joern_java_bin/java"; then :; else fail "JOERN_JAVA_BIN 未提供 java"; fi
  elif probe_executable "Joern 所用 Java" "java"; then
    :
  else
    fail "Java 不可用"
  fi

  if [ -n "$joern_gnubin" ]; then
    if (PATH="$joern_gnubin:$PATH"; command -v greadlink >/dev/null 2>&1); then
      pass "Joern 所需 GNU readlink 可用"
    else
      fail "JOERN_GNUBIN 未提供 greadlink"
    fi
  fi

  if [ -n "$joern_parse_path" ] && "$joern_parse_path" --list-languages 2>/dev/null | grep -qi '^[- ]*python'; then
    pass "Joern 声明支持 Python 前端"
  elif [ -n "$joern_parse_path" ]; then
    warn "Joern 未声明支持 Python 前端"
  fi

  if [ "$check_python" = true ]; then
    if [ -z "$joern_parse_path" ]; then
      fail "缺少 joern-parse，无法运行 Python 前端冒烟检查"
    else
      python_probe_dir="$(mktemp -d "${TMPDIR:-/tmp}/opencode-initial.XXXXXX")"
      trap 'rm -rf "$python_probe_dir"' EXIT
      printf 'def health_check(value):\n    return value\n' > "$python_probe_dir/source.py"
      if "$joern_parse_path" "$python_probe_dir/source.py" -o "$python_probe_dir/cpg.bin" --language python \
        >"$python_probe_dir/parse.stdout.log" 2>"$python_probe_dir/parse.stderr.log" \
        && [ -s "$python_probe_dir/cpg.bin" ]; then
        pass "Joern Python 前端冒烟检查"
      else
        python_probe_diagnostic="$(
          {
            tail -n 20 "$python_probe_dir/parse.stderr.log"
            tail -n 20 "$python_probe_dir/parse.stdout.log"
          } 2>/dev/null | tail -c 4000
        )"
        fail "Joern Python 前端冒烟检查失败；诊断尾部：${python_probe_diagnostic:-无输出}"
      fi
    fi
  else
    info "未执行 Python 前端检查；Python 项目请使用 --python"
  fi
fi

if [ "$check_mcp" = true ]; then
  printf '\n本地 MCP 健康状态\n'
  if [ "$node_ok" = true ] && [ "$config_ok" = true ] && [ "$dependencies_ok" = true ]; then
    if check_mcp_health; then
      pass "本地 MCP 健康检查"
    else
      fail "本地 MCP 健康检查"
    fi
  else
    warn "Node.js、依赖或配置检查失败，跳过本地 MCP 健康检查"
  fi
fi

if [ "$run_tests" = true ]; then
  printf '\n回归测试\n'
  if npm --prefix .opencode test; then
    pass "项目回归测试"
  else
    fail "项目回归测试"
  fi
fi

printf '\n初始化结果：%s 项失败，%s 项警告\n' "$failures" "$warnings"
if [ "$failures" -gt 0 ]; then
  info "解决每一项【失败】后，重新运行 ./initial.sh"
  exit 1
fi
info "基础初始化已就绪；仅在需要 Python 审计、最终三方复核或完整回归时使用对应参数"
