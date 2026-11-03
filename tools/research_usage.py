"""How much an opencode research session read and spent: characters its tools returned, and model tokens.

    python3 -I tools/research_usage.py SESSION_ID                    one session, as one line
    python3 -I tools/research_usage.py --dir REPO [--since MS]       every session run in REPO (since an epoch-ms time)
    python3 -I tools/research_usage.py --dir REPO --since MS --into BATCH.json
                                                                     the latest such session, recorded in a batch file

"Read" is the text the tools returned (files, diffs, API responses); tokens are what the provider counted: fresh
input, cached re-reads of the conversation, output and reasoning. Standard library only; needs `opencode`.
"""

import json
import subprocess
import sys
import tempfile
import time
from pathlib import Path

# Ollama Cloud prices, USD per million tokens (input, cached input, output), from https://ollama.com/pricing on
# 2026-11-03. Off-peak (outside 12:00-18:00 UTC on weekdays, and weekends) is half. Unknown models cost None.
PRICES = {"deepseek-v4.1-flash:cloud": (0.30, 0.006, 1.20), "kimi-k3:cloud": (3.00, 0.30, 15.00)}


def cost(model, tokens, started_ms):
    price = PRICES.get(model)
    if price is None:
        return None
    when = time.gmtime(started_ms / 1000)
    peak = when.tm_wday < 5 and 12 <= when.tm_hour < 18
    fresh, cached, out = price
    total = (tokens["input"] * fresh + tokens["cache_read"] * cached
             + (tokens["output"] + tokens["reasoning"]) * out) / 1e6
    return round(total if peak else total / 2, 3)


def _opencode(*args, cwd=None):
    """opencode's JSON output (sessions are listed per project, so run it in the session's folder). Written to a
    file, not a pipe: through a pipe, large exports come back cut short."""
    with tempfile.TemporaryFile("w+") as out_file:
        subprocess.run(["opencode", *args], check=True, stdout=out_file, stderr=subprocess.DEVNULL, cwd=cwd)
        out_file.seek(0)
        out = out_file.read()
    starts = [i for i in (out.find("{"), out.find("[")) if i >= 0]
    return json.loads(out[min(starts):]) if starts else []


def sessions(directory, since=0):
    found = _opencode("session", "list", "--format", "json", "-n", "500", cwd=directory)
    return sorted((s for s in found if s.get("directory") == directory and s.get("created", 0) >= since),
                  key=lambda s: s["created"])


def usage(session_id, cwd=None):
    data = _opencode("export", session_id, cwd=cwd)
    tokens = {"input": 0, "cache_read": 0, "output": 0, "reasoning": 0}
    turns = calls = refused = read = 0
    model = ""
    for message in data["messages"]:
        info = message["info"]
        if info.get("role") != "assistant":
            continue
        turns += 1
        model = info.get("modelID", model)
        t = info.get("tokens", {})
        tokens["input"] += t.get("input", 0)
        tokens["cache_read"] += t.get("cache", {}).get("read", 0)
        tokens["output"] += t.get("output", 0)
        tokens["reasoning"] += t.get("reasoning", 0)
        for part in message["parts"]:
            if part.get("type") == "tool":
                calls += 1
                state = part.get("state", {})
                refused += state.get("status") == "error"
                read += len(str(state.get("output", "")))
    info = data["info"]
    created, updated = info.get("time", {}).get("created", 0), info.get("time", {}).get("updated", 0)
    return {"session": session_id, "model": model, "minutes": round((updated - created) / 60000),
            "turns": turns, "tool_calls": calls, "tool_errors": refused, "chars_read": read, "tokens": tokens,
            "usd": cost(model, tokens, created)}


def line(u):
    t = u["tokens"]
    return (f"{u['session']} {u['model']}: {u['minutes']} min, {u['turns']} turns, {u['tool_calls']} tool calls "
            f"({u['tool_errors']} failed), {u['chars_read']:,} chars read; tokens {t['input']:,} in + "
            f"{t['cache_read']:,} cached + {t['output'] + t['reasoning']:,} out"
            + (f"; ~${u['usd']:.2f}" if u.get("usd") is not None else ""))


def main(argv):
    if argv and not argv[0].startswith("--"):
        print(line(usage(argv[0])))
        return 0
    opts = dict(zip(argv[::2], argv[1::2], strict=True))
    found = sessions(str(Path(opts["--dir"]).resolve()), int(opts.get("--since", 0)))
    if not found:
        print("no opencode session found")
        return 1
    if "--into" in opts:
        u = usage(found[-1]["id"], cwd=found[-1]["directory"])
        path = Path(opts["--into"])
        batch = json.loads(path.read_text())
        batch["usage"] = u
        path.write_text(json.dumps(batch, indent=2, ensure_ascii=False) + "\n")
        print(line(u))
        return 0
    for s in found:
        print(line(usage(s["id"], cwd=s["directory"])))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
