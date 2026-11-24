"""Invoke the protected existing endpoint once and print its fixed code only."""

import json
import os
import re
import subprocess
import sys
import tempfile

URL_PATTERN = re.compile(r"https://adp-training-portal-[a-z0-9]+-uther\.vercel\.app\Z")
CODE_PATTERN = re.compile(r"ADP-GOLD-RUNTIME-(?:READY|DISABLED|CONFIG|NETWORK|READINESS|HTTP-(?:401|403|404|4XX|5XX|UNEXPECTED))\Z")


def run(args, cwd):
    result = subprocess.run(args, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            check=False, timeout=90)
    if result.returncode:
        diagnostic = (result.stderr + result.stdout).decode("utf-8", errors="replace").lower()
        if "not authorized" in diagnostic or "unauthorized" in diagnostic or "invalid token" in diagnostic:
            raise RuntimeError("CLI_AUTH")
        if "forbidden" in diagnostic or "insufficient" in diagnostic:
            raise RuntimeError("CLI_PERMISSION")
        if "unknown option" in diagnostic or "unknown argument" in diagnostic:
            raise RuntimeError("CLI_ARGUMENT")
        if "project" in diagnostic and ("not found" in diagnostic or "not linked" in diagnostic):
            raise RuntimeError("CLI_PROJECT")
        if "deployment" in diagnostic and "not found" in diagnostic:
            raise RuntimeError("CLI_DEPLOYMENT")
        raise RuntimeError("CLI_FAILURE")
    return result.stdout.decode("utf-8", errors="replace")


def main():
    url = os.environ.get("ADP_GOLD_DEPLOYMENT_URL", "")
    vercel_token = os.environ.get("VERCEL_TOKEN", "")
    probe_token = os.environ.get("ADP_GOLD_RUNTIME_TOKEN", "")
    if not URL_PATTERN.fullmatch(url) or not vercel_token or len(probe_token) < 32:
        raise RuntimeError("CONFIG")
    with tempfile.TemporaryDirectory() as work:
        response = run(["vercel", "curl", url + "/api/diagnostics/gold-runtime",
                        "--scope", "uther", "--token", vercel_token,
                        "--", "-sS", "-H", "x-adp-gold-runtime: " + probe_token], work)
    payload = json.loads(response)
    code = payload.get("code")
    if not isinstance(code, str) or not CODE_PATTERN.fullmatch(code) or type(payload.get("ok")) is not bool:
        raise RuntimeError("UNEXPECTED_RESPONSE")
    print("GATE0_RUNTIME_CODE=" + code)
    if code != "ADP-GOLD-RUNTIME-READY" or payload["ok"] is not True:
        raise RuntimeError("NOT_READY")


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        # Never print CLI stderr/stdout, URLs, tokens, response bodies or tracebacks.
        reason = str(error) if isinstance(error, RuntimeError) else "UNEXPECTED_FAILURE"
        if reason not in ("CONFIG", "CLI_FAILURE", "CLI_AUTH", "CLI_PERMISSION", "CLI_ARGUMENT", "CLI_PROJECT", "CLI_DEPLOYMENT", "UNEXPECTED_RESPONSE", "NOT_READY"):
            reason = "UNEXPECTED_FAILURE"
        print("::error::GATE0_RUNTIME_" + reason, file=sys.stderr)
        sys.exit(1)
