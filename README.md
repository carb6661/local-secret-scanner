# Local Secret Scanner

一个零依赖、仅在本机运行的 Python 工具，用于在你拥有或明确获授权检查的代码目录中发现常见的疑似敏感信息。它不会联网、不会上传文件，也会在终端输出中对匹配内容脱敏。

> 本项目用于发布前自检与安全教学，不能替代专业的密钥管理、代码审查或完整的安全审计。

## 功能

- 识别常见的 AWS 访问密钥、GitHub Token、私钥 PEM 头和高风险赋值语句
- 跳过 `.git`、虚拟环境、依赖目录、二进制文件及大于 1 MB 的文件
- 只显示脱敏后的匹配片段，避免终端日志二次泄漏
- 支持 CI：`--fail-on-findings` 在发现结果时返回退出码 `1`
- 不含网络访问、上传或任何凭据使用行为

## 快速开始

```bash
git clone https://github.com/carb6661/local-secret-scanner.git
cd local-secret-scanner
python secret_scanner.py /path/to/your/project
```

用于 CI 或提交前检查：

```bash
python secret_scanner.py /path/to/your/project --fail-on-findings
```

额外忽略目录：

```bash
python secret_scanner.py /path/to/your/project --ignore fixtures --ignore generated
```

## 示例输出

```text
config/.env:4 [assignment with likely secret] API_…cdef
发现 1 个疑似敏感信息匹配项（输出已脱敏）。
```

## 运行测试

```bash
python -m unittest discover -s tests -v
```

## 项目结构

```text
├── secret_scanner.py        # 扫描规则、脱敏和命令行入口
├── tests/test_secret_scanner.py
├── pyproject.toml
└── README.md
```

## 学习要点

1. **检测结果需要人工确认**：正则匹配会有误报，也不可能覆盖所有密钥格式。
2. **发现凭据后应立即轮换**：从 Git 历史删除字符串并不等于凭据失效。
3. **不要把真正的密钥写进测试用例**：本项目的测试使用占位值。
4. **最好的防线是预防**：使用环境变量、密钥管理服务和提交前扫描。

## 许可证

[MIT](LICENSE)
