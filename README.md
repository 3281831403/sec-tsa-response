给存证加了时间戳之后，拿旧的响应文件替换新的，序列号完全没人校验：摘要只比较长度；摘要算法按默认值而不按响应声明；序列号只校验非负；序列号记录不查重；时间窗只校验过旧；时间窗允许零长度；签发者白名单用后缀比较；签名比较用普通等号；记录序列号不持久化；批量校验复用序列号记录，tsa/verify.py 是核心，tests/unit/test_verify.py 15个红。要修的是：按上面的顺序把 10 个缺陷逐个修掉。

# 题目说明

这是一个时间戳机构响应校验器的修复题。响应对象把摘要算法、摘要值、序列号、签发时间、签发者和签名放在一起；校验器必须同时保证摘要绑定、序列号单调、时效、重放防护和签发者授权，任何一个环节松动都会让旧响应文件重新生效。

题目仓库只提供 8 个桩。实现者需要保持公开签名不变，在 `tsa/verify.py` 中完成实现。测试是唯一契约，`tests` 目录不可修改。

# 字段表

| 字段 | 值 |
| --- | --- |
| 题目类型 | 安全 |
| 题目方向 | 漏洞检测与攻防 |
| 题目难度 | 非常难 |
| 修复类型 | Bugfix |
| 技术栈 | Python 3, pytest |
| 外部依赖 | 无外部依赖 |

# 目录结构

```text
sec-tsa-response/
├── README.md
├── conftest.py
├── tsa/
│   ├── __init__.py
│   └── verify.py
└── tests/
    ├── unit/
    │   └── test_verify.py
    └── behaviour/
        └── test_verify_edge.py
```

# 运行方式

在仓库根目录执行：

```powershell
python -m pytest tests -q
```

初始状态必须恰好为：

```text
15 failed
```

并且 15 个失败全部是 `NotImplementedError`，不允许出现收集错误、导入错误或断言失败。测试文件本身不得修改；唯一需要修改的实现文件是 `tsa/verify.py`。

# 测试拆分布局

测试按契约层和行为层拆开，合计 15 条：

- `tests/unit/test_verify.py`：10 条契约测试，一条对应一个规格缺陷。
- `tests/behaviour/test_verify_edge.py`：5 条边界测试，覆盖合法路径、摘要不符、序列号回退、过期响应和批量一致性。

单元测试：

1. `test_digest_comparison_requires_full_digest_not_length`
2. `test_digest_uses_declared_algorithm_after_migration`
3. `test_serial_must_be_strictly_greater_than_ledger_max`
4. `test_same_serial_cannot_be_recorded_twice`
5. `test_future_timestamp_outside_window_is_rejected`
6. `test_zero_length_window_is_rejected`
7. `test_issuer_whitelist_uses_exact_match_not_suffix`
8. `test_signature_comparison_uses_constant_time_digest`
9. `test_serial_ledger_persists_across_restart`
10. `test_batch_keeps_each_response_serial_independent`

行为测试：

1. `test_valid_response_passes_every_check`
2. `test_imprint_mismatch_is_rejected`
3. `test_serial_rollback_is_rejected`
4. `test_expired_response_is_rejected`
5. `test_two_batches_match_individual_verification`

# 十个缺陷与测试映射

| 序号 | 规格缺陷 | 捕获测试 |
| --- | --- | --- |
| 1 | 摘要只比较长度，长度相同即通过 | `test_digest_comparison_requires_full_digest_not_length` |
| 2 | 摘要算法按默认值计算而不按响应声明，算法迁移后全失配 | `test_digest_uses_declared_algorithm_after_migration` |
| 3 | 序列号只校验非负，未要求严格递增 | `test_serial_must_be_strictly_greater_than_ledger_max` |
| 4 | 序列号记录不查重，同一响应可反复使用 | `test_same_serial_cannot_be_recorded_twice` |
| 5 | 时间窗只校验是否过旧，未来时间戳被接受 | `test_future_timestamp_outside_window_is_rejected` |
| 6 | 时间窗允许窗口为零，零长度窗口通过 | `test_zero_length_window_is_rejected` |
| 7 | 签发者白名单用后缀比较，相似签发者命中 | `test_issuer_whitelist_uses_exact_match_not_suffix` |
| 8 | 签名比较用普通等号 | `test_signature_comparison_uses_constant_time_digest` |
| 9 | 记录序列号不持久化，重启后重放通过 | `test_serial_ledger_persists_across_restart` |
| 10 | 批量校验复用序列号记录，第二个响应沿用第一个响应的序列号 | `test_batch_keeps_each_response_serial_independent` |

# 响应格式与 API 契约

`parse_response(raw)` 接收 UTF-8 JSON 字节串，返回规范化映射。原始响应形状如下：

```json
{
  "algorithm": "sha256",
  "digest": "64-character lowercase hex",
  "serial": 1000,
  "time": "2026-11-19T12:00:00Z",
  "issuer": "tsa.trusted.example",
  "signature": "64-character lowercase hex"
}
```

返回映射必须包含同样的六个键。其中 `algorithm` 为小写算法名，`digest` 与 `signature` 为小写十六进制字符串，`serial` 为正整数，`time` 为带时区的 UTC `datetime`，`issuer` 为原始精确字符串。

签名固定为 HMAC-SHA256，密钥为字节串。被签名的规范化 JSON 只包含 `algorithm`、`digest`、`issuer`、`serial`、`time` 五个键，使用 `sort_keys=True`、`separators=(",", ":")`、`ensure_ascii=False`，并以 UTF-8 编码；`time` 在该对象中格式化为 `YYYY-MM-DDTHH:MM:SSZ`。签名比较必须调用 `hmac.compare_digest`。

序列号账本是 JSON 文件，形状如下：

```json
{"max_serial": 0, "used": []}
```

`check_serial(response, store)` 只在序列号为正整数、严格大于 `max_serial` 且不在 `used` 中时返回 `True`。账本不存在时视为空账本。`record_serial(store, response)` 成功时追加序列号并写盘，返回 `accepted`、`reason`、`max_serial`、`used`；重复或回退时返回 `accepted` 为 `False`，`reason` 为 `"serial_reuse"`，不得改动账本。

时间窗参数是 `datetime.timedelta`。当且仅当窗口严格大于零且响应时间落在闭区间 `[now - window, now + window]` 内时，`check_time` 返回 `True`。签发者白名单是精确、区分大小写的成员判断。

`tsa_batch(responses, policy, now)` 按顺序处理原始响应字节串。`policy` 含 `store`、`allowed_issuers`、`window`、`key`、`documents` 五项；`documents` 是整数序列号到原件字节串的映射。批量校验使用账本的私有视图，单条响应失败不影响后续响应；同一批内重复序列号只接受第一次，成功后统一持久化。返回：

```json
{
  "results": [
    {"index": 0, "serial": 1000, "accepted": true, "reason": null}
  ],
  "accepted": [1000],
  "rejected": []
}
```

# 约束

- 不得修改 `tests` 目录。
- 不得引入外部依赖，标准库即可完成。
- 不得改变 `tsa/verify.py` 中 8 个公开函数的名称和参数。
- 修复顺序按题面列出的 10 个缺陷顺序进行。
- 初始 15 个测试必须全红且全为 `NotImplementedError`；完成后必须 15 个测试全绿。

## 字段表

| 字段 | 取值 |
| --- | --- |
| 所属领域 | 安全 |
| 子方向 | 漏洞检测与攻防 |
| 任务类型 | Bugfix |
| 语言/框架 | Python 3, pytest |
| 环境可复现等级 | 无外部依赖 |

