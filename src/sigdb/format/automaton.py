from __future__ import annotations

from collections import deque
from collections.abc import Sequence

from sigdb.types import Automaton, FormatError
from sigdb.utils.varint import decode_varint, encode_varint


def build_automaton(patterns: Sequence[tuple[bytes, int]]) -> Automaton:
    trans: list[dict[int, int]] = [{}]
    out: list[list[int]] = [[]]

    for pattern_bytes, pattern_id in patterns:
        state = 0
        for b in pattern_bytes:
            nxt = trans[state].get(b)
            if nxt is None:
                nxt = len(trans)
                trans[state][b] = nxt
                trans.append({})
                out.append([])
            state = nxt
        out[state].append(pattern_id)

    for i in range(len(out)):
        if len(out[i]) > 1:
            out[i] = sorted(set(out[i]))

    fail: list[int] = [0] * len(trans)
    q: deque[int] = deque(trans[0].values())
    while q:
        v = q.popleft()
        for b, u in trans[v].items():
            q.append(u)
            f = fail[v]
            while f != 0 and b not in trans[f]:
                f = fail[f]
            fail[u] = trans[f].get(b, 0)
            if out[fail[u]]:
                out[u] = sorted(set(out[u]) | set(out[fail[u]]))

    node_count = len(trans)
    children_start: list[int] = [0] * node_count
    children_count: list[int] = [0] * node_count
    out_start: list[int] = [0] * node_count
    out_count: list[int] = [0] * node_count
    labels = bytearray()
    next_state: list[int] = []
    outputs: list[int] = []

    for i in range(node_count):
        edges = sorted(trans[i].items())
        children_start[i] = len(labels)
        children_count[i] = len(edges)
        for b, nxt in edges:
            labels.append(b)
            next_state.append(nxt)
        out_start[i] = len(outputs)
        out_count[i] = len(out[i])
        outputs.extend(out[i])

    return Automaton(
        children_start=children_start,
        children_count=children_count,
        fail=fail,
        out_start=out_start,
        out_count=out_count,
        labels=bytes(labels),
        next_state=next_state,
        outputs=outputs,
    )


def serialize_automaton(a: Automaton) -> bytes:
    out = bytearray()
    node_count = len(a.children_start)
    out += encode_varint(node_count)
    out += encode_varint(len(a.labels))
    out += encode_varint(len(a.outputs))
    for i in range(node_count):
        out += encode_varint(a.children_start[i])
        out += encode_varint(a.children_count[i])
        out += encode_varint(a.fail[i])
        out += encode_varint(a.out_start[i])
        out += encode_varint(a.out_count[i])
    out += a.labels
    for nxt in a.next_state:
        out += encode_varint(nxt)
    for pattern_id in a.outputs:
        out += encode_varint(pattern_id)
    return bytes(out)


def deserialize_automaton(data: bytes, *, pattern_count: int) -> Automaton:
    pos = 0

    def read() -> int:
        nonlocal pos
        r = decode_varint(data, pos)
        pos = r.offset
        return r.value

    node_count = read()
    edge_count = read()
    output_total = read()
    if node_count < 1 or node_count * 5 + edge_count * 2 + output_total > len(data):
        raise FormatError("automaton counts exceed block size")

    children_start = [0] * node_count
    children_count = [0] * node_count
    fail = [0] * node_count
    out_start = [0] * node_count
    out_count = [0] * node_count
    for i in range(node_count):
        children_start[i] = read()
        children_count[i] = read()
        fail[i] = read()
        out_start[i] = read()
        out_count[i] = read()

    if pos + edge_count > len(data):
        raise FormatError("truncated automaton labels")
    labels = bytes(data[pos : pos + edge_count])
    pos += edge_count
    next_state = [read() for _ in range(edge_count)]
    outputs = [read() for _ in range(output_total)]

    if pos != len(data):
        raise FormatError("automaton block has trailing bytes")

    for i in range(node_count):
        if children_start[i] + children_count[i] > edge_count:
            raise FormatError("automaton edge range out of bounds")
        if out_start[i] + out_count[i] > output_total:
            raise FormatError("automaton output range out of bounds")
        if fail[i] >= node_count:
            raise FormatError("automaton fail link out of bounds")
    if any(n >= node_count or n == 0 for n in next_state):
        raise FormatError("automaton transition out of bounds")
    if any(p >= pattern_count for p in outputs):
        raise FormatError("automaton output references unknown pattern")

    return Automaton(
        children_start=children_start,
        children_count=children_count,
        fail=fail,
        out_start=out_start,
        out_count=out_count,
        labels=labels,
        next_state=next_state,
        outputs=outputs,
    )


def find_contains(a: Automaton, data: bytes) -> list[tuple[int, int]]:
    found: list[tuple[int, int]] = []
    state = 0
    for i, b in enumerate(data):
        while True:
            nxt = a.transition(state, b)
            if nxt != -1:
                state = nxt
                break
            if state == 0:
                break
            state = a.fail[state]
        if a.out_count[state]:
            end = i + 1
            found.extend((end, pattern_id) for pattern_id in a.outputs_of(state))
    return found


def find_prefix(a: Automaton, data: bytes, lengths: Sequence[int]) -> list[tuple[int, int]]:
    found: list[tuple[int, int]] = []
    state = 0
    for depth, b in enumerate(data, start=1):
        state = a.transition(state, b)
        if state == -1:
            break
        if a.out_count[state]:
            found.extend(
                (depth, pattern_id)
                for pattern_id in a.outputs_of(state)
                if lengths[pattern_id] == depth
            )
    return found
