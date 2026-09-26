# 读写仲裁交集分析器

该服务枚举存储实例中所有可行的读、写仲裁集，并判断：

1. 读侧是否仍能形成满足权重门槛和机房覆盖要求的仲裁集；
2. 写侧是否仍能形成满足权重门槛和机房覆盖要求的仲裁集；
3. 两侧均可行时，所有可行读写对的最小交集大小；
4. 若最小交集为 0，按规则返回一对真实不相交的读写反例。

离线副本不会进入任何仲裁集。权重阈值之和不是充分判据：机房覆盖会迫使不同仲裁集选择不同副本，因此必须枚举可行仲裁集后检查交集。

## 输入协议

`POST /analyze` 接收 UTF-8 JSON：

```json
{
  "replicas": [
    {"id": "a1", "weight": 6, "datacenter": "A", "online": true},
    {"id": "a2", "weight": 6, "datacenter": "A", "online": true},
    {"id": "b1", "weight": 6, "datacenter": "B", "online": true},
    {"id": "b2", "weight": 6, "datacenter": "B", "online": true}
  ],
  "read": {"weight_threshold": 12, "required_datacenters": ["A", "B"]},
  "write": {"weight_threshold": 12, "required_datacenters": ["A", "B"]}
}
```

约束：

- `replicas`：2～12 个对象；
- `id`：非空 ASCII 字符串，且在实例内唯一；
- `weight`：1～9 的整数；
- `datacenter`：非空 ASCII 字符串；
- `online`：布尔值；
- `read.weight_threshold`、`write.weight_threshold`：非负整数，缺省为 0；
- `required_datacenters`：非空 ASCII 机房名数组，同层不得重复，缺省为空。

阈值为 0 且没有机房要求时，空仲裁集可行。

可选的 `recovery_plan`：布尔值，缺省为 `false`。为 `true` 时输出额外的
`recovery_plan` 字段，规划应恢复哪些当前离线副本。

## 输出协议

两侧均可行时：

- `minimum_intersection`：所有可行读写对的最小交集成员数；
- `witness_read`、`witness_write`：达到该最小交集的一对仲裁集；
- `safe`：仅当最小交集大于 0 时为 `true`。

若任意一侧没有可行仲裁集，最小交集为 `null`，`safe` 保持 `false`，避免无可行仲裁集时误报安全。

当最小交集为 0，`disjoint_counterexample` 提供实际不相交反例。多个并列反例按以下顺序选择：

1. 两集合总成员数最少；
2. 读侧排序后的 id 列表字典序最小；
3. 写侧排序后的 id 列表字典序最小。

示例：

```json
{
  "read_possible": true,
  "write_possible": true,
  "minimum_intersection": 0,
  "witness_read": {"replica_ids": ["a1", "b1"]},
  "witness_write": {"replica_ids": ["a2", "b2"]},
  "disjoint_counterexample": {
    "read": {"replica_ids": ["a1", "b1"]},
    "write": {"replica_ids": ["a2", "b2"]}
  },
  "safe": false
}
```

非法请求返回 HTTP 400 和 `{"error": "..."}`。

## 恢复规划

`recovery_plan: true`（CLI 使用 `--recovery-plan`）时，仅以当前离线副本为
候选，按 **(恢复数量, 排序后的副本 id 列表字典序)** 枚举候选子集；每个子集
都把对应副本翻为在线后，严格按原权重门槛、机房覆盖与在线语义重新完整
裁决。安全意味着恢复后两侧均可行**且**所有可行读写仲裁集仍相交
（`safe: true`），而不是“读、写各自可行”。

可达时返回恢复数量最少的唯一安全集合（并列取字典序最小），以及恢复后
真实的可行性、最小交集和达到该交集的一对见证：

```json
{
  "recovery_plan": {
    "reachable": true,
    "restore_replica_ids": ["c"],
    "read_possible": true,
    "write_possible": true,
    "minimum_intersection": 1,
    "witness_read": {"replica_ids": ["a", "b", "c"]},
    "witness_write": {"replica_ids": ["a"]}
  }
}
```

- 当前已满足条件时，`restore_replica_ids` 为 `[]`，见证取自当前裁决；
- 不存在任何安全恢复集合时，`reachable` 为 `false`，其余字段为 `null`。

恢复在线副本只会**新增**可行仲裁集，因而可能引入新的不相交读写对：
更大的恢复集合（例如恢复全部离线副本）不一定安全，所以必须逐子集裁决，
不能假设多恢复一个副本必然改善交集。空仲裁集（阈值为 0 且无机房要求）
恒可行且与任何仲裁集不相交，属于典型的不可达场景。


## 本地命令行

从标准输入读取：

```bash
python3 -m quorum < examples/disjoint.json
```

或指定文件：

```bash
python3 -m quorum examples/safe.json
```

启用恢复规划：

```bash
python3 -m quorum --recovery-plan examples/recovery_plan.json
```

CLI 在输入无效时向 stderr 输出错误并返回退出码 2。

## Docker Compose 服务

启动：

```bash
docker compose up --build
```

请求：

```bash
curl -fsS http://127.0.0.1:8080/analyze \
  -H 'Content-Type: application/json' \
  --data-binary @examples/disjoint.json
```

健康检查：

```bash
curl -fsS http://127.0.0.1:8080/health
```

## 算法

副本数最多为 12，所以每侧最多只有 `2^12 = 4096` 个候选集合。服务用位掩码枚举全部在线子集，检查权重和以及所有必需机房是否至少有一个副本被选中，然后对两侧可行集合求交集。

可行掩码按 `(成员数, 掩码数值)` 排序；按 id 排序后，相同成员数掩码的数值递增等价于 id 列表字典序递增。反例枚举据此实现总成员数和两侧 id 列表的裁决规则。

恢复规划复用同一份裁决：离线副本至多 12 个，按恢复数量和 id 列表字典序
枚举子集（最多 4096 个），逐子集翻转在线位后重新枚举可行仲裁集并检查
交集，命中的第一个安全集合即数量最少且字典序唯一的答案。

## 开发与测试

开发依赖见 `requirements-dev.txt`：

```bash
python3 -m pip install -r requirements-dev.txt
pytest
```

测试包含：

- 小实例位掩码枚举对拍；
- 随机实例对拍；
- 离线副本；
- 机房约束；
- 相等权重并列；
- 总成员数优先于字典序；
- CLI 和 HTTP 服务；
- 恢复规划：跨机房多副本恢复、空仲裁集不可达、并列最优取字典序、
  恢复更多副本反而引入不相交仲裁、各自可行但不安全、已安全返回空集合；
- 恢复规划随机实例的独立子集枚举对拍；
- 未启用规划时 CLI/HTTP/库输出与原协议一致。
