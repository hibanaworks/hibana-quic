#!/usr/bin/env python3
"""Enumerate all finite handoff interleavings on ONE queue of capacity one.

This mirrors direct send/recv sequences in application/startup.rs. It is a
source-level queue model, not execution of Hibana, its carrier, Rust futures,
owned Rust capabilities, QUIC, or an interop test. External IO is outside these
finite handoffs. The previous whole TaskSet has completed before each starts.
"""
from collections import deque
import json
from pathlib import Path


def send(a, b, label): return ('send', a, b, label)
def recv(a, b, label): return ('recv', a, b, label)


def explore(actors):
    start = (tuple(0 for _ in actors), None)
    seen = {start}
    pending = deque([start])
    terminal = 0
    deadlocks = []
    while pending:
        counters, queue = pending.popleft()
        if all(at == len(actor) for at, actor in zip(counters, actors)):
            assert queue is None
            terminal += 1
            continue
        successors = []
        for index, (at, actor) in enumerate(zip(counters, actors)):
            if at == len(actor): continue
            operation, sender, receiver, label = actor[at]
            frame = (sender, receiver, label)
            if operation == 'send':
                if queue is not None: continue
                next_queue = frame
            else:
                if queue != frame: continue
                next_queue = None
            next_counters = list(counters)
            next_counters[index] += 1
            successors.append((tuple(next_counters), next_queue))
        if not successors: deadlocks.append({'counters': counters, 'queue': queue})
        for state in successors:
            if state not in seen:
                seen.add(state)
                pending.append(state)
    return {'reachable_states': len(seen), 'terminal_states': terminal,
            'nonterminal_deadlocks': deadlocks}


def main():
    scenarios = {
        'actual_write_finished_admission_round_trip': [
            [send(2, 13, 162)],
            [recv(2, 13, 162), send(13, 0, 167), recv(10, 13, 165)],
            [recv(13, 0, 167), send(0, 1, 160)],
            [recv(0, 1, 160), send(1, 10, 161)],
            [recv(1, 10, 161), send(10, 13, 165)],
        ],
        'actual_key_control_and_stream_admission': [
            [send(13, 12, 166), send(13, 16, 164)],
            [recv(13, 12, 166)],
            [recv(13, 16, 164), send(16, 8, 163)],
            [recv(16, 8, 163)],
        ],
        'actual_accumulated_retirement_grants': [
            [send(16, 26, 55), recv(26, 16, 54)],
            [recv(26, 12, 57), send(12, 26, 53)],
            [recv(26, 23, 58), send(23, 26, 56)],
            [recv(26, 25, 59), send(25, 26, 52)],
            [recv(16, 26, 55), send(26, 12, 57), recv(12, 26, 53),
             send(26, 23, 58), recv(23, 26, 56), send(26, 25, 59),
             recv(25, 26, 52), send(26, 16, 54)],
        ],
        # Negative control: two unsolicited origins and a fixed receive order.
        'rejected_unordered_parallel_receive_design': [
            [send(2, 13, 162)], [send(10, 13, 165)],
            [recv(2, 13, 162), recv(10, 13, 165)],
        ],
    }
    results = {name: explore(actors) for name, actors in scenarios.items()}
    for name, result in results.items():
        if name.startswith('actual_'):
            assert result['terminal_states'] == 1
            assert not result['nonterminal_deadlocks'], (name, result)
        else:
            assert result['nonterminal_deadlocks'], 'negative control failed to expose Q=1 blockage'
        print(name, result)
    Path(__file__).with_name('finite_q1_result.json').write_text(json.dumps({
        'caveat': __doc__, 'results': results}, indent=2) + '\n')


if __name__ == '__main__': main()
