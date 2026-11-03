"""First-pass triage of a nightly report's app findings by Ollama cloud models; a Claude session confirms.

For each finding (new since the previous report, or all of them with --all or on a first report), the code around
the flagged line goes to two models, which each answer REAL or FALSE_ALARM with a reason. Where they disagree a
third decides. Writes triage.md (false-alarm drafts first: they're what the rules need) and triage.json next to the
report. Standard library only; needs the Ollama server at localhost:11434. Never point it at blind repositories.

    python3 -I benchmarks/triage.py [NIGHTLY_DIR] [--all] [--limit N]
"""

import json
import sys
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

NIGHTLY = Path.home() / ".cache" / "codewatch" / "nightly"
APPS = Path.home() / ".config" / "codewatch" / "nightly-apps.txt"
OLLAMA = "http://127.0.0.1:11434/api/chat"
# Picked on 2026-11-02 from 14 labelled findings: both 14/14 and fast; kimi-k3 was the sharpest on a hard case.
MODELS = ("deepseek-v4.1-flash:cloud", "beam:cloud")
TIEBREAK = "kimi-k3:cloud"
PARALLEL = 3  # Ollama Cloud answers HTTP 429 above this
CONTEXT = 40

PROMPT = """You review findings from codewatch, a static security scanner for web applications.
A rule flagged line {line} of {path} in the project "{app}" as: {rule}.

Decide whether this is a REAL vulnerability or a FALSE_ALARM. REAL means data an attacker controls (an HTTP request's
parameters, body, headers, cookies, path or uploaded files) can reach this line and cause the weakness the rule
names, with no effective protection on the way (escaping, autoescaping templates, parameterised queries, a working
allowlist or containment check, a constant value). If the code shown doesn't show where the data comes from, judge
from names and call sites as well as you can, and say what you assumed.

Some rules flag an insecure setting rather than a data flow (cookie flags, weak hashes, disabled TLS checks, debug
mode, weak randomness). For those, REAL means the setting is insecure where it matters (a session or auth cookie, a
password or token hash, a secret), and FALSE_ALARM means it doesn't matter there (a UI-preference cookie, a
non-security checksum or cache key).

The code (line numbers on the left, the flagged line marked with >>):
{code}

Answer with JSON only: {{"verdict": "REAL" or "FALSE_ALARM", "reason": "one or two sentences"}}"""


def app_dirs():
    dirs = {}
    for raw in APPS.read_text().splitlines():
        entry = raw.split("#", 1)[0].strip()
        if entry:
            path = Path(entry.replace("~", str(Path.home()), 1))
            if "blind" not in path.parts and not any(part.startswith("blind") for part in path.parts):
                dirs[path.name] = path
    return dirs


def findings(report, everything):
    """[(app, path, line, rule)] to triage."""
    current = (report / "apps.txt").read_text().splitlines()
    earlier = sorted(p for p in NIGHTLY.glob("20??-??-??") if p.name < report.name and (p / "apps.txt").exists())
    if earlier and not everything:
        seen = set((earlier[-1] / "apps.txt").read_text().splitlines())
        current = [x for x in current if x not in seen]
    return [tuple(x.split(" ", 3)) for x in current if x.count(" ") >= 3]


def code_around(root, path, line):
    lines = (root / path).read_text(errors="replace").splitlines()
    first, last = max(1, line - CONTEXT), min(len(lines), line + CONTEXT)
    return "\n".join(f"{'>>' if n == line else '  '}{n:5} {lines[n - 1]}" for n in range(first, last + 1))


def ask(model, prompt):
    body = json.dumps({"model": model, "stream": False, "format": "json", "options": {"temperature": 0},
                       "messages": [{"role": "user", "content": prompt}]}).encode()
    for attempt in range(4):
        try:
            request = urllib.request.Request(OLLAMA, body, {"Content-Type": "application/json"})
            with urllib.request.urlopen(request, timeout=300) as response:
                answer = json.loads(json.loads(response.read())["message"]["content"])
            verdict = str(answer.get("verdict", "")).upper().replace(" ", "_")
            if verdict in ("REAL", "FALSE_ALARM"):
                return verdict, str(answer.get("reason", "")).strip()
        except Exception as error:  # noqa: BLE001 - network, HTTP 429, bad JSON: retry, then report
            if attempt == 3:
                return "ERROR", f"{type(error).__name__}: {error}"[:200]
        time.sleep(5 * (attempt + 1))
    return "ERROR", "no usable answer"


def triage(finding, dirs):
    app, path, line, rule = finding
    root = dirs.get(app)
    result = {"app": app, "path": path, "line": int(line), "rule": rule}
    if root is None or not (root / path).is_file():
        return {**result, "verdict": "ERROR", "votes": {}, "reason": "file not found"}
    prompt = PROMPT.format(app=app, path=path, line=line, rule=rule, code=code_around(root, path, int(line)))
    votes = {model: ask(model, prompt) for model in MODELS}
    verdicts = {v for v, _ in votes.values() if v != "ERROR"}
    if len(verdicts) != 1:
        votes[TIEBREAK] = ask(TIEBREAK, prompt)
        decided = votes[TIEBREAK][0]
    else:
        decided = verdicts.pop()
    reason = next((r for v, r in votes.values() if v == decided), "")
    return {**result, "verdict": decided, "agreed": len(votes) == len(MODELS), "reason": reason,
            "votes": {m: v for m, (v, _) in votes.items()}}


def write(report, results):
    (report / "triage.json").write_text(json.dumps(results, indent=1) + "\n")
    order = {"FALSE_ALARM": 0, "REAL": 1, "ERROR": 2}
    out = [f"# Triage drafts for {report.name} (Ollama: {', '.join(MODELS)}; ties: {TIEBREAK})", "",
           "Drafts only: a Claude session confirms each before it drives a rule change.", "",
           "| Verdict | Agreed | Finding | Reason |", "|---|---|---|---|"]
    for r in sorted(results, key=lambda r: (order.get(r["verdict"], 3), r["app"], r["path"], r["line"])):
        reason = r["reason"].replace("|", "\\|").replace("\n", " ")
        out.append(f"| {r['verdict']} | {'yes' if r.get('agreed') else 'no'} | "
                   f"{r['app']} {r['path']}:{r['line']} {r['rule']} | {reason} |")
    (report / "triage.md").write_text("\n".join(out) + "\n")


def main(argv):
    everything = "--all" in argv
    limit = int(argv[argv.index("--limit") + 1]) if "--limit" in argv else 300
    named = [a for a in argv if not a.startswith("--") and not a.isdigit()]
    reports = sorted(p for p in NIGHTLY.glob("20??-??-??") if (p / "apps.txt").exists())
    report = Path(named[0]) if named else (reports[-1] if reports else None)
    if report is None or not (report / "apps.txt").exists():
        print("no nightly report with apps.txt")
        return 1
    todo = findings(report, everything)[:limit]
    dirs = app_dirs()
    with ThreadPoolExecutor(PARALLEL) as pool:
        results = list(pool.map(lambda f: triage(f, dirs), todo))
    write(report, results)
    counts = {v: sum(r["verdict"] == v for r in results) for v in ("REAL", "FALSE_ALARM", "ERROR")}
    print(f"triage: {len(results)} findings, " + ", ".join(f"{n} {v}" for v, n in counts.items()))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
