import argparse
import getpass
import sys

from .hibp import BreachCheckError, breach_count, http_fetch
from .strength import analyse


def check_one(password: str, offline: bool = False, fetch=http_fetch) -> dict:
    result = {"strength": analyse(password), "breaches": None, "error": None}
    if not offline:
        result["breaches"] = breach_count(password, fetch)
    return result


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pwcheck",
        description="Breach-aware password checker (HIBP k-anonymity + local strength scoring).",
    )
    p.add_argument("--offline", action="store_true", help="skip the breach lookup")
    return p

EXIT_OK = 0
EXIT_BREACHED = 1
EXIT_ERROR = 2


def verdict(result: dict) -> str:
    if result["breaches"]:
        return "DO NOT USE - found in breaches"
    if result["strength"].score <= 1:
        return "Weak - choose something longer"
    if result["breaches"] is None:
        return "Strength OK (breach status unknown)"
    return "OK - not found in known breaches"


def exit_code(result: dict) -> int:
    if result["breaches"]:
        return EXIT_BREACHED
    if result["error"]:
        return EXIT_ERROR
    return EXIT_OK


def render(result: dict, label: str | None = None) -> str:
    r = result["strength"]
    lines = []
    if label:
        lines.append(f"== {label} ==")
    lines.append(f"Strength : {r.label} ({r.score}/4), ~{r.entropy_bits} bits, {r.length} chars")
    if result["error"]:
        lines.append(f"Breaches : unknown ({result['error']})")
    elif result["breaches"] is None:
        lines.append("Breaches : not checked (offline mode)")
    elif result["breaches"] == 0:
        lines.append("Breaches : not found in known breach data")
    else:
        lines.append(f"Breaches : seen {result['breaches']:,} times in breach data")
    for w in r.warnings:
        lines.append(f"  - {w}")
    lines.append(f"Verdict  : {verdict(result)}")
    return "\n".join(lines)

def main(argv=None, fetch=http_fetch) -> int:
    args = build_parser().parse_args(argv)
    pw = getpass.getpass("Password to check (input hidden): ")
    result = check_one(pw, args.offline, fetch)
    print(render(result))
    return exit_code(result)