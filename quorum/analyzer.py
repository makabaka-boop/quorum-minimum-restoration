"""枚举在线副本的读、写仲裁集并检查交集安全性。

副本数最多为 12，因此直接枚举 4096 个集合掩码。权重门槛与机房覆盖是
两个不同维度：仅凭读、写权重阈值之和不能推断两侧仲裁集必相交。

可选的恢复规划只把当前离线副本视为候选：对每个候选子集把对应副本翻为
在线后，严格复用同一套权重、机房与在线枚举重新裁决，挑出恢复数量最少
的安全集合。恢复在线副本只会新增可行仲裁集，因而可能引入新的不相交
读写对，安全性并不随恢复数量单调，必须逐子集裁决而不能直接恢复全部。
"""

from __future__ import annotations

import dataclasses
from dataclasses import dataclass
from itertools import combinations
from typing import Any, Mapping


class ValidationError(ValueError):
    """输入 JSON 不符合协议。"""


@dataclass(frozen=True)
class _Side:
    threshold: int
    required_datacenters: tuple[str, ...]


@dataclass(frozen=True)
class _Replica:
    replica_id: str
    weight: int
    datacenter: str
    online: bool


def _is_non_empty_ascii(value: Any) -> bool:
    return isinstance(value, str) and len(value) > 0 and value.isascii()


def _as_int(value: Any, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValidationError(f"{field} must be an integer")
    if value < 0:
        raise ValidationError(f"{field} must be non-negative")
    return value


def _as_str_list(value: Any, field: str) -> list[str]:
    if not isinstance(value, list) or not all(
        isinstance(item, str) for item in value
    ):
        raise ValidationError(f"{field} must be a list of strings")
    items = list(value)
    if any(not item or not item.isascii() for item in items):
        raise ValidationError(f"{field} must contain non-empty ASCII strings")
    return items


def _side(spec: Any, name: str) -> _Side:
    if not isinstance(spec, Mapping):
        raise ValidationError(f"{name} must be an object")

    required = _as_str_list(
        spec.get("required_datacenters", []),
        f"{name}.required_datacenters",
    )
    if len(required) != len(set(required)):
        raise ValidationError(f"{name}.required_datacenters must be unique")

    return _Side(
        threshold=_as_int(spec.get("weight_threshold", 0), f"{name}.weight_threshold"),
        required_datacenters=tuple(required),
    )


def _parse_replicas(value: Any) -> list[_Replica]:
    if not isinstance(value, list):
        raise ValidationError("replicas must be a list")
    if not 2 <= len(value) <= 12:
        raise ValidationError("replicas must contain between 2 and 12 entries")

    replicas: list[_Replica] = []
    seen: set[str] = set()
    for index, item in enumerate(value):
        field = f"replicas[{index}]"
        if not isinstance(item, Mapping):
            raise ValidationError(f"{field} must be an object")

        replica_id = item.get("id")
        if not _is_non_empty_ascii(replica_id):
            raise ValidationError(f"{field}.id must be a non-empty ASCII string")
        assert isinstance(replica_id, str)
        if replica_id in seen:
            raise ValidationError(f"duplicate replica id: {replica_id}")
        seen.add(replica_id)

        weight = item.get("weight")
        if isinstance(weight, bool) or not isinstance(weight, int):
            raise ValidationError(f"{field}.weight must be an integer between 1 and 9")
        if not 1 <= weight <= 9:
            raise ValidationError(f"{field}.weight must be an integer between 1 and 9")

        datacenter = item.get("datacenter")
        if not _is_non_empty_ascii(datacenter):
            raise ValidationError(
                f"{field}.datacenter must be a non-empty ASCII string"
            )
        assert isinstance(datacenter, str)

        online = item.get("online")
        if not isinstance(online, bool):
            raise ValidationError(f"{field}.online must be a boolean")

        replicas.append(
            _Replica(
                replica_id=replica_id,
                weight=weight,
                datacenter=datacenter,
                online=online,
            )
        )

    # 所有裁决均使用固定 id 字典序，避免输入顺序影响并列反例。
    replicas.sort(key=lambda replica: replica.replica_id)
    return replicas


def _required_masks(replicas: list[_Replica]) -> dict[str, int]:
    masks: dict[str, int] = {}
    for index, replica in enumerate(replicas):
        masks.setdefault(replica.datacenter, 0)
        masks[replica.datacenter] |= 1 << index
    return masks


def _feasible_masks(
    replicas: list[_Replica],
    side: _Side,
    datacenter_masks: Mapping[str, int],
    online_mask: int,
) -> list[int]:
    """返回按 (成员数, id 列表字典序) 排序的可行仲裁集。"""
    required_masks: list[int] = []
    for datacenter in side.required_datacenters:
        if datacenter not in datacenter_masks:
            return []
        required_masks.append(datacenter_masks[datacenter])

    n = len(replicas)
    mask_weights = [0] * (1 << n)
    for index, replica in enumerate(replicas):
        bit = 1 << index
        for mask in range(bit):
            mask_weights[bit | mask] = mask_weights[mask] + replica.weight

    result: list[int] = []

    for mask in range(1 << n):
        if mask & ~online_mask:
            continue
        if mask_weights[mask] < side.threshold:
            continue
        if any(not (mask & required) for required in required_masks):
            continue
        result.append(mask)

    # 对相同成员数的掩码，数值递增等于排序后的 id 列表字典序递增。
    result.sort(key=lambda mask: (mask.bit_count(), mask))
    return result


def _mask_to_ids(mask: int, replica_ids: list[str]) -> list[str]:
    return [
        replica_ids[index]
        for index in range(len(replica_ids))
        if mask & (1 << index)
    ]


def _witness(mask: int, replica_ids: list[str]) -> dict[str, list[str]]:
    return {"replica_ids": _mask_to_ids(mask, replica_ids)}


def _adjudicate(
    replicas: list[_Replica],
    read: _Side,
    write: _Side,
) -> dict[str, Any]:
    """对给定副本状态完整枚举并裁决一次，返回稳定的 JSON 兼容结果。"""
    datacenter_masks = _required_masks(replicas)
    replica_ids = [replica.replica_id for replica in replicas]
    online_mask = 0
    for index, replica in enumerate(replicas):
        if replica.online:
            online_mask |= 1 << index

    read_masks = _feasible_masks(replicas, read, datacenter_masks, online_mask)
    write_masks = _feasible_masks(replicas, write, datacenter_masks, online_mask)
    read_possible = bool(read_masks)
    write_possible = bool(write_masks)

    result: dict[str, Any] = {
        "read_possible": read_possible,
        "write_possible": write_possible,
        "minimum_intersection": None,
        "witness_read": None,
        "witness_write": None,
        "disjoint_counterexample": None,
        "safe": False,
    }

    if not read_possible or not write_possible:
        return result

    best_intersection: int | None = None
    best_read = 0
    best_write = 0

    for read_mask in read_masks:
        for write_mask in write_masks:
            intersection = (read_mask & write_mask).bit_count()
            if best_intersection is None or intersection < best_intersection:
                best_intersection = intersection
                best_read = read_mask
                best_write = write_mask
                if best_intersection == 0:
                    break
        if best_intersection == 0:
            break

    assert best_intersection is not None
    result["minimum_intersection"] = best_intersection
    result["witness_read"] = _witness(best_read, replica_ids)
    result["witness_write"] = _witness(best_write, replica_ids)

    if best_intersection > 0:
        result["safe"] = True
        return result

    # 仅在确实存在不相交读写对时选择反例。排序顺序保证成员数优先；
    # 成员总数相同的候选再比较读、写两侧排序后的 id 列表。
    disjoint_read: int | None = None
    disjoint_write: int | None = None
    best_total = len(replicas) * 2 + 1
    best_key: tuple[list[str], list[str]] | None = None

    for read_mask in read_masks:
        read_size = read_mask.bit_count()
        if read_size > best_total:
            break
        for write_mask in write_masks:
            write_size = write_mask.bit_count()
            total_size = read_size + write_size
            if total_size > best_total:
                break
            if read_mask & write_mask:
                continue

            candidate_key = (
                _mask_to_ids(read_mask, replica_ids),
                _mask_to_ids(write_mask, replica_ids),
            )
            if disjoint_read is None or total_size < best_total or (
                total_size == best_total
                and (best_key is None or candidate_key < best_key)
            ):
                disjoint_read = read_mask
                disjoint_write = write_mask
                best_total = total_size
                best_key = candidate_key

    assert disjoint_read is not None
    assert disjoint_write is not None
    result["disjoint_counterexample"] = {
        "read": _witness(disjoint_read, replica_ids),
        "write": _witness(disjoint_write, replica_ids),
    }

    return result


def _plan_recovery(
    replicas: list[_Replica],
    read: _Side,
    write: _Side,
    current: Mapping[str, Any],
) -> dict[str, Any]:
    """在离线副本中寻找恢复数量最少且恢复后安全的集合。

    候选子集按 (恢复数量, id 列表字典序) 枚举；每个子集都重新完整裁决，
    因此恢复后反而出现不相交仲裁对的集合会被正确判为不安全。
    """
    if current["safe"]:
        # 已满足条件：不需要恢复任何副本，恢复后的裁决即当前裁决。
        return {
            "reachable": True,
            "restore_replica_ids": [],
            "read_possible": current["read_possible"],
            "write_possible": current["write_possible"],
            "minimum_intersection": current["minimum_intersection"],
            "witness_read": current["witness_read"],
            "witness_write": current["witness_write"],
        }

    offline = [replica for replica in replicas if not replica.online]
    for size in range(1, len(offline) + 1):
        for chosen in combinations(offline, size):
            chosen_ids = {replica.replica_id for replica in chosen}
            adjusted = [
                dataclasses.replace(replica, online=True)
                if replica.replica_id in chosen_ids
                else replica
                for replica in replicas
            ]
            outcome = _adjudicate(adjusted, read, write)
            if outcome["safe"]:
                return {
                    "reachable": True,
                    "restore_replica_ids": [
                        replica.replica_id for replica in chosen
                    ],
                    "read_possible": outcome["read_possible"],
                    "write_possible": outcome["write_possible"],
                    "minimum_intersection": outcome["minimum_intersection"],
                    "witness_read": outcome["witness_read"],
                    "witness_write": outcome["witness_write"],
                }

    return {
        "reachable": False,
        "restore_replica_ids": None,
        "read_possible": None,
        "write_possible": None,
        "minimum_intersection": None,
        "witness_read": None,
        "witness_write": None,
    }


def analyze(payload: Mapping[str, Any], *, recovery_plan: bool = False) -> dict[str, Any]:
    """分析输入并返回稳定的 JSON 兼容结果。

    恢复规划默认关闭；payload 中的 ``"recovery_plan": true`` 或关键字参数
    均可开启。未开启时输出与原协议完全一致。
    """
    if not isinstance(payload, Mapping):
        raise ValidationError("request body must be a JSON object")

    flag = payload.get("recovery_plan", False)
    if not isinstance(flag, bool):
        raise ValidationError("recovery_plan must be a boolean")

    replicas = _parse_replicas(payload.get("replicas"))
    read = _side(payload.get("read", {}), "read")
    write = _side(payload.get("write", {}), "write")

    result = _adjudicate(replicas, read, write)
    if recovery_plan or flag:
        result["recovery_plan"] = _plan_recovery(replicas, read, write, result)
    return result
