# MIME Audit Service（科研归档平台 · 邮件附件审计）

在提取邮件附件之前，本服务确认邮件的 **MIME 层级、边界与传输编码只有一种解释**，
避免邮件客户端容错解析后保存出与归档证据不一致的文件。任何结构或编码错误都会
拒绝整封邮件——绝不输出部分附件清单。

仅使用 Python 标准库实现，镜像构建无需联网安装依赖。

## API

### `POST /api/mime/audit`

- 请求 `Content-Type: message/rfc822`，必须带 `Content-Length`，消息体 ≤ 4 MiB，
  且全程只能使用 CRLF 换行（不允许裸 LF / 裸 CR）。
- `GET /healthz` 返回 `{"status": "ok"}`，用于健康检查。

**成功（200）**：按深度优先（先序）顺序列出全部附件，`part` 为部件序号
（先序实体编号，根实体为 0），`size` 为**解码后**字节数，`sha256` 为解码字节的小写哈希。

```json
{
  "attachments": [
    {"part": 3, "filename": "report.pdf", "media_type": "application/pdf",
     "size": 1040, "sha256": "41dc4368…"}
  ],
  "attachment_count": 1,
  "leaf_count": 4,
  "max_depth": 4
}
```

**拒绝（4xx）**：稳定错误码 + 可定位的部件序号，不含任何附件清单。

```json
{"error": {"code": "BOUNDARY_NOT_CLOSED", "part": 0,
           "message": "closing boundary delimiter is missing"}}
```

## 校验规则

结构：

- 根实体必须是 `multipart/mixed`；嵌套深度 ≤ 4 层（根实体为第 1 层）；
  叶子（非 multipart 实体）≤ 64 个。
- 边界必须语法合法（1–70 个 bchars，首尾非空格）、正确闭合、全邮件不得复用；
  正文中不得出现以 `--boundary` 开头却非法定分隔符的行（消除前缀歧义，
  嵌套边界也不得是祖先边界的前缀扩展）。preamble/epilogue 按 RFC 2046 忽略。
- 头部必须为 7 位 ASCII；`Content-Type` / `Content-Disposition` /
  `Content-Transfer-Encoding` / `MIME-Version` 不得重复；参数名不得重复。

编码：

- 每个叶子必须显式声明 `Content-Transfer-Encoding`，且只接受严格
  **Base64**（标准字母表、行 ≤ 76、padding 仅在末尾且补齐、pad bits 为零的
  规范形式）或严格 **quoted-printable**（合法 `=XX` 转义、软换行、行 ≤ 76、
  无行尾空白、无裸 8 位/控制字节）。multipart 实体不得使用 base64/QP 编码。

附件与文件名：

- 附件 = 带 `Content-Disposition: attachment` 且文件名唯一的叶子；
  其余叶子（inline / 无 disposition）会被解码校验但不列入清单。
- 文件名取自 `filename` 或 UTF-8 的 `filename*`（RFC 2231 单段形式，
  字符集必须 utf-8，非 attr-char 必须百分号编码）；两者并存时解码结果必须一致。
  不支持 `filename*0*` 等续段形式（明确拒绝而非猜测）。
- 文件名经 NFC 规范化并去除首尾空白后：不得为空、不得含路径成分
  （`/`、`\`、`.`、`..`）、附件之间不得重复。
- 叶子缺 `Content-Type` 时媒体类型按 RFC 默认为 `text/plain`。

## 错误码（稳定）

| 分类 | 错误码 |
| --- | --- |
| 消息级 | `MESSAGE_TOO_LARGE`(413)、`EMPTY_MESSAGE`、`NON_CRLF_LINE_ENDING` |
| 请求级 | `INVALID_REQUEST_CONTENT_TYPE`(415)、`MISSING_CONTENT_LENGTH`(400)、`UNSUPPORTED_REQUEST_TRANSFER_ENCODING`(400)、`TRUNCATED_BODY`(400)、`NOT_FOUND`(404) |
| 头部 | `MALFORMED_HEADER`、`DUPLICATE_HEADER`、`UNSUPPORTED_MIME_VERSION`、`INVALID_CONTENT_TYPE`、`INVALID_CONTENT_DISPOSITION`、`DUPLICATE_PARAMETER` |
| 结构 | `ROOT_NOT_MULTIPART_MIXED`、`MAX_DEPTH_EXCEEDED`、`TOO_MANY_LEAVES`、`EMPTY_MULTIPART`、`MALFORMED_PART`、`MISSING_BOUNDARY`、`INVALID_BOUNDARY`、`BOUNDARY_DELIMITER_MISSING`、`BOUNDARY_NOT_CLOSED`、`BOUNDARY_REUSED`、`AMBIGUOUS_BOUNDARY_LINE`、`MULTIPART_TRANSFER_ENCODING` |
| 编码 | `MISSING_TRANSFER_ENCODING`、`UNSUPPORTED_TRANSFER_ENCODING`、`INVALID_BASE64`、`INVALID_QUOTED_PRINTABLE` |
| 文件名 | `MISSING_FILENAME`、`INVALID_FILENAME`、`INVALID_FILENAME_STAR`、`UNSUPPORTED_FILENAME_CONTINUATION`、`FILENAME_MISMATCH`、`FILENAME_EMPTY`、`FILENAME_PATH_COMPONENT`、`DUPLICATE_FILENAME` |

`part` 为先序实体序号（根 = 0）；消息级/请求级错误为 `null`。

## 运行

```bash
docker compose up app                 # 启动服务（默认宿主机 8080 端口）
MIME_AUDIT_PORT=9000 docker compose up app   # 宿主机端口可配置
curl -s http://127.0.0.1:8080/healthz
curl -s -X POST http://127.0.0.1:8080/api/mime/audit \
     -H 'Content-Type: message/rfc822' --data-binary @sample.eml
```

## 验证（一次性 verify 服务）

`verify` 服务与 `app` 共用同一镜像：先运行解析器单元测试，再向健康检查通过后的
`app` 提交合法嵌套邮件（4 层嵌套、3 个附件，逐一比对文件名/媒体类型/解码字节数/
SHA-256 与顺序）和损坏边界样例（根边界未闭合、内层边界未闭合，校验错误码与部件
序号），最后以退出码汇报结果并自行结束：

```bash
docker compose up --exit-code-from verify verify   # 退出码即 verify 的退出码
docker compose down
```

本地（无 Docker）同样可验证：

```bash
python3 -m app.main &                 # 监听 127.0.0.1:8080
python3 -m app.verify                 # 单元 + 集成测试，退出码汇报结果
```

## 设计说明

- 自研严格解析器而非 `email` 包：标准库解析器以容错为目标，同一封畸形邮件可能
  解析出不同结构，无法满足"只有一种解释"的归档要求。
- 有意的严格子集：拒绝 RFC 2231 续段文件名、RFC 2047 encoded-word、裸 8 位头部、
  非规范 Base64（pad bits 非零）、嵌套边界与祖先边界构成前缀关系等——这些情形
  在不同客户端间解释不一致，拒绝比猜测更安全。
- 错误检测顺序固定（消息级 → 头部 → 结构 → 编码 → 文件名），同一输入永远产生
  同一错误码与部件序号；合法邮件的清单只取决于解码后的真实字节。
