"""恢复规划的独立测试：候选仅为离线副本，逐子集重新裁决。

对拍器直接复用 test_analyzer 中面向原始协议的独立枚举实现，
再按 (恢复数量, id 列表字典序) 自行枚举离线子集，与被测实现完全分离。
"""

import itertools
import json
import subprocess
import sys
import threading
import urllib.request
from pathlib import Path

import pytest

from quorum.analyzer import ValidationError, analyze
from quorum.server import build_server
from test_analyzer import expected_analysis, make_payload, replica

ROOT = Path(__file__).resolve().parents[1]


def expected_plan(payload):
    """独立枚举离线子集，返回期望的 recovery_plan 结构。"""
    base = expected_analysis(payload)
    if base["safe"]:
        return {
            "reachable": True,
            "restore_replica_ids": [],
            "read_possible": base["read_possible"],
            "write_possible": base["write_possible"],
            "minimum_intersection": base["minimum_intersection"],
            "witness_read": base["witness_read"],
            "witness_write": base["witness_write"],
        }

    replicas = sorted(payload["replicas"], key=lambda item: item["id"])
    offline = [item for item in replicas if not item["online"]]
    for size in range(1, len(offline) + 1):
        for chosen in itertools.combinations(offline, size):
            chosen_ids = {item["id"] for item in chosen}
            adjusted = make_payload(
                [
                    replica(
                        item["id"],
                        item["weight"],
                        item["datacenter"],
                        online=item["online"] or item["id"] in chosen_ids,
                    )
                    for item in payload["replicas"]
                ],
                read_threshold=payload["read"]["weight_threshold"],
                write_threshold=payload["write"]["weight_threshold"],
                read_dcs=payload["read"]["required_datacenters"],
                write_dcs=payload["write"]["required_datacenters"],
            )
            outcome = expected_analysis(adjusted)
            if outcome["safe"]:
                return {
                    "reachable": True,
                    "restore_replica_ids": [
                        item["id"] for item in chosen
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


def analyze_with_plan(payload):
    return analyze(payload, recovery_plan=True)


def test_cross_datacenter_restore_needs_one_replica_per_missing_region():
    payload = make_payload(
        [
            replica("a1", 3, "A"),
            replica("a2", 3, "A"),
            replica("b1", 3, "B", online=False),
            replica("c1", 3, "C", online=False),
        ],
        read_threshold=7,
        write_threshold=7,
        read_dcs=["A", "B"],
        write_dcs=["A", "C"],
    )

    result = analyze_with_plan(payload)

    assert result["read_possible"] is False
    assert result["write_possible"] is False
    # 读侧缺 B、写侧缺 C：只恢复 b1 或只恢复 c1 都有一侧不可行，
    # 必须跨机房各恢复一个。
    assert result["recovery_plan"] == {
        "reachable": True,
        "restore_replica_ids": ["b1", "c1"],
        "read_possible": True,
        "write_possible": True,
        "minimum_intersection": 2,
        "witness_read": {"replica_ids": ["a1", "a2", "b1"]},
        "witness_write": {"replica_ids": ["a1", "a2", "c1"]},
    }


def test_empty_read_quorum_can_never_be_safe():
    payload = make_payload(
        [replica("a", 1), replica("b", 1, online=False)],
        read_threshold=0,
        write_threshold=2,
    )

    result = analyze_with_plan(payload)

    # 空仲裁集永远可行且与任何写仲裁集不相交，恢复全部副本也无济于事。
    assert result["recovery_plan"] == {
        "reachable": False,
        "restore_replica_ids": None,
        "read_possible": None,
        "write_possible": None,
        "minimum_intersection": None,
        "witness_read": None,
        "witness_write": None,
    }


def test_empty_quorums_on_both_sides_stay_unsafe_after_full_restore():
    payload = make_payload(
        [replica("a", 1, online=False), replica("b", 1, online=False)],
        read_threshold=0,
        write_threshold=0,
    )

    result = analyze_with_plan(payload)

    assert result["read_possible"] is True
    assert result["write_possible"] is True
    assert result["safe"] is False
    assert result["recovery_plan"]["reachable"] is False
    assert result["recovery_plan"]["restore_replica_ids"] is None


def test_tied_single_replica_restores_pick_lexicographically_smallest():
    payload = make_payload(
        [
            replica("a1", 5, "A"),
            replica("b1", 5, "B", online=False),
            replica("b2", 5, "B", online=False),
        ],
        read_threshold=5,
        write_threshold=5,
        read_dcs=["A"],
        write_dcs=["A", "B"],
    )

    result = analyze_with_plan(payload)

    # 恢复 b1 或 b2 都能达到最小交集 1，按 id 列表字典序取 b1。
    assert result["recovery_plan"] == {
        "reachable": True,
        "restore_replica_ids": ["b1"],
        "read_possible": True,
        "write_possible": True,
        "minimum_intersection": 1,
        "witness_read": {"replica_ids": ["a1"]},
        "witness_write": {"replica_ids": ["a1", "b1"]},
    }


def test_restoring_more_replicas_can_introduce_disjoint_quorums():
    payload = make_payload(
        [
            replica("a", 1),
            replica("b", 1),
            replica("c", 1, online=False),
            replica("d", 1, online=False),
        ],
        read_threshold=3,
        write_threshold=1,
    )

    result = analyze_with_plan(payload)

    # 当前读侧不可行；恢复 c（或并列的 d）即可安全，但继续恢复 d 会
    # 让 {a,b,d} 与 {c} 成为不相交读写对，因此不能假设多恢复必然更好。
    assert result["recovery_plan"] == {
        "reachable": True,
        "restore_replica_ids": ["c"],
        "read_possible": True,
        "write_possible": True,
        "minimum_intersection": 1,
        "witness_read": {"replica_ids": ["a", "b", "c"]},
        "witness_write": {"replica_ids": ["a"]},
    }

    fully_restored = make_payload(
        [replica(name, 1) for name in ("a", "b", "c", "d")],
        read_threshold=3,
        write_threshold=1,
    )
    restored_result = analyze(fully_restored)
    assert restored_result["read_possible"] is True
    assert restored_result["write_possible"] is True
    assert restored_result["minimum_intersection"] == 0
    assert restored_result["safe"] is False


def test_read_and_write_possible_alone_is_not_enough():
    payload = make_payload(
        [
            replica("a1", 5, "A"),
            replica("a2", 5, "A"),
            replica("b1", 5, "B", online=False),
        ],
        read_threshold=5,
        write_threshold=5,
        write_dcs=["B"],
    )

    result = analyze_with_plan(payload)

    # 恢复 b1 后读写各自可行，但 {a1} 与 {b1} 不相交，必须报告不可达。
    assert result["recovery_plan"]["reachable"] is False
    assert result["recovery_plan"]["restore_replica_ids"] is None


def test_already_safe_returns_empty_restore_set():
    payload = make_payload(
        [
            replica("a1", 4, "A"),
            replica("a2", 4, "A"),
            replica("b1", 4, "B"),
            replica("b2", 4, "B"),
        ],
        read_threshold=12,
        write_threshold=12,
        read_dcs=["A", "B"],
        write_dcs=["A", "B"],
    )

    result = analyze_with_plan(payload)

    assert result["safe"] is True
    assert result["recovery_plan"] == {
        "reachable": True,
        "restore_replica_ids": [],
        "read_possible": True,
        "write_possible": True,
        "minimum_intersection": 2,
        "witness_read": {"replica_ids": ["a1", "a2", "b1"]},
        "witness_write": {"replica_ids": ["a1", "a2", "b2"]},
    }


def test_no_offline_candidates_and_unsafe_is_unreachable():
    payload = make_payload(
        [
            replica("a1", 6, "A"),
            replica("a2", 6, "A"),
            replica("b1", 6, "B"),
            replica("b2", 6, "B"),
        ],
        read_threshold=12,
        write_threshold=12,
        read_dcs=["A", "B"],
        write_dcs=["A", "B"],
    )

    result = analyze_with_plan(payload)

    assert result["safe"] is False
    assert result["recovery_plan"]["reachable"] is False
    assert result["recovery_plan"]["restore_replica_ids"] is None


def test_plan_disabled_by_default_and_with_explicit_false():
    payload = make_payload(
        [replica("a", 1), replica("b", 1, online=False)],
        read_threshold=2,
        write_threshold=2,
    )

    default_result = analyze(payload)
    assert "recovery_plan" not in default_result

    false_flag = dict(payload, recovery_plan=False)
    assert analyze(false_flag) == default_result

    keyword_off = analyze(payload, recovery_plan=False)
    assert "recovery_plan" not in keyword_off


def test_payload_flag_enables_planning():
    payload = make_payload(
        [replica("a", 1), replica("b", 1, online=False)],
        read_threshold=2,
        write_threshold=2,
    )
    flagged = dict(payload, recovery_plan=True)

    assert analyze(flagged) == analyze(payload, recovery_plan=True)
    assert analyze(flagged)["recovery_plan"]["restore_replica_ids"] == ["b"]


@pytest.mark.parametrize(
    "bad_payload,message",
    [
        (
            dict(
                make_payload([replica("a"), replica("b")]),
                recovery_plan="yes",
            ),
            "recovery_plan must be a boolean",
        ),
        (
            dict(make_payload([replica("a", 10), replica("b")]),
                 recovery_plan=True),
            "between 1 and 9",
        ),
        (
            dict(make_payload([replica("same"), replica("same")]),
                 recovery_plan=True),
            "duplicate replica id",
        ),
    ],
)
def test_invalid_input_produces_no_partial_plan(bad_payload, message):
    with pytest.raises(ValidationError, match=message):
        analyze(bad_payload, recovery_plan=True)


def random_plan_payload(seed):
    rng = __import__("random").Random(seed)
    n = rng.randint(2, 8)
    ids = [f"r{index:02d}-{rng.randrange(36):x}" for index in range(n)]
    assert len(set(ids)) == n
    datacenters = [rng.choice(["dc-a", "dc-b", "dc-c"]) for _ in range(n)]
    replicas = [
        replica(
            identifier,
            weight=rng.randint(1, 9),
            dc=datacenter,
            online=rng.random() >= 0.45,
        )
        for identifier, datacenter in zip(ids, datacenters)
    ]

    def side():
        dc_options = sorted(set(datacenters))
        required = rng.sample(dc_options, rng.randrange(len(dc_options) + 1))
        return {
            "weight_threshold": rng.randrange(0, 25),
            "required_datacenters": required,
        }

    return {"replicas": replicas, "read": side(), "write": side()}


@pytest.mark.parametrize("seed", range(40))
def test_random_instances_match_independent_subset_enumeration(seed):
    payload = random_plan_payload(seed)
    result = analyze(payload, recovery_plan=True)
    assert result == {
        **expected_analysis(payload),
        "recovery_plan": expected_plan(payload),
    }


def test_cli_recovery_plan_flag_matches_library_call():
    payload = make_payload(
        [replica("a", 1), replica("b", 1, online=False)],
        read_threshold=2,
        write_threshold=2,
    )
    completed = subprocess.run(
        [sys.executable, "-m", "quorum", "--recovery-plan"],
        input=json.dumps(payload),
        text=True,
        capture_output=True,
        cwd=ROOT,
        check=False,
    )

    assert completed.returncode == 0
    assert json.loads(completed.stdout) == analyze(payload, recovery_plan=True)


def test_cli_without_flag_keeps_original_output():
    payload = make_payload(
        [replica("a", 1), replica("b", 1, online=False)],
        read_threshold=2,
        write_threshold=2,
    )
    completed = subprocess.run(
        [sys.executable, "-m", "quorum"],
        input=json.dumps(payload),
        text=True,
        capture_output=True,
        cwd=ROOT,
        check=False,
    )

    assert completed.returncode == 0
    assert json.loads(completed.stdout) == expected_analysis(payload)


def test_cli_invalid_input_with_flag_reports_error_without_plan():
    completed = subprocess.run(
        [sys.executable, "-m", "quorum", "--recovery-plan"],
        input=json.dumps({"replicas": [], "recovery_plan": True}),
        text=True,
        capture_output=True,
        cwd=ROOT,
        check=False,
    )

    assert completed.returncode == 2
    assert completed.stdout == ""
    assert "between 2 and 12" in completed.stderr


def test_http_plan_flag_in_body_matches_library_call():
    server = build_server("127.0.0.1", 0)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        payload = dict(
            make_payload(
                [replica("a", 1), replica("b", 1, online=False)],
                read_threshold=2,
                write_threshold=2,
            ),
            recovery_plan=True,
        )
        request = urllib.request.Request(
            f"http://127.0.0.1:{port}/analyze",
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=5) as response:
            assert response.status == 200
            assert json.loads(response.read()) == analyze(
                payload, recovery_plan=True
            )

        plain = dict(payload)
        del plain["recovery_plan"]
        plain_request = urllib.request.Request(
            f"http://127.0.0.1:{port}/analyze",
            data=json.dumps(plain).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(plain_request, timeout=5) as response:
            body = json.loads(response.read())
            assert "recovery_plan" not in body
            assert body == expected_analysis(plain)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
