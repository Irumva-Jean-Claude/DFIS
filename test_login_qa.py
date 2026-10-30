"""Pytest harness that runs login_qa.mjs via Node and fails on assertion errors.

Requires: node, playwright installed in the Node context, and the QA_USER /
QA_PASS environment variables. Optionally QA_TOTP and the app URL (QA_URL).
Run: pytest test_login_qa.py -v
"""
import json
import os
import shutil
import subprocess
import textwrap
import pathlib

HERE = pathlib.Path(__file__).parent
SCRIPT = HERE / "login_qa.mjs"
DRIVER = HERE / "_run_login_qa.mjs"

DRIVER_SRC = textwrap.dedent("""
    import { chromium } from 'playwright';
    import run from './login_qa.mjs';

    const url = (process.env.QA_URL || 'http://localhost:3000').replace(/localhost/g, '127.0.0.1');
    const launchOpts = {
      executablePath: 'C:\\Users\\JClaude\\AppData\\Local\\ms-playwright\\chromium-1248\\chrome-win64\\chrome.exe'
    };
    if (process.env.PW_EXECUTABLE) {
      launchOpts.executablePath = process.env.PW_EXECUTABLE;
    }
    const browser = await chromium.launch({ channel: 'msedge' }).catch(() => chromium.launch({ channel: 'chrome' }));
    const page = await browser.newPage();
    try {
      await page.goto(url, { waitUntil: 'domcontentloaded' });
      const result = await run(page);
      console.log('RESULT:' + JSON.stringify(result));
    } finally {
      await browser.close();
    }
""")

REQUIRED_ENV = ("QA_USER", "QA_PASS")


def _write_driver():
    src = DRIVER_SRC
    exe = os.environ.get("PW_EXECUTABLE")
    if exe:
        marker = "executablePath: "
        idx = src.find(marker)
        if idx != -1:
            line_end = src.find("\n", idx)
            src = src[:idx] + marker + json.dumps(exe) + src[line_end:]
    DRIVER.write_text(src, encoding="utf-8")


def _require_env():
    missing = [v for v in REQUIRED_ENV if not os.environ.get(v)]
    if missing:
        raise RuntimeError(
            "Missing environment variables for login QA: "
            + ", ".join(missing)
            + ". Set QA_USER and QA_PASS before running."
        )


def _run_script():
    """Run the QA script in Node, return the parsed result JSON."""
    _write_driver()
    if shutil.which("node") is None:
        raise RuntimeError("Node.js is required to run login_qa.mjs but was not found on PATH.")
    try:
        proc = subprocess.run(
            ["node", DRIVER.name],
            cwd=str(HERE),
            capture_output=True,
            text=True,
            timeout=120,
        )
    except subprocess.TimeoutExpired:
        raise RuntimeError("login_qa.mjs timed out after 120s.")
    if proc.returncode != 0:
        raise RuntimeError(f"login_qa.mjs failed (exit {proc.returncode}):\n{proc.stderr}")
    for line in proc.stdout.splitlines():
        if line.startswith("RESULT:"):
            return json.loads(line[len("RESULT:"):])
    raise RuntimeError(f"login_qa.mjs produced no RESULT line.\nstdout:\n{proc.stdout}")


def test_login_mfa_form_state():
    _require_env()
    result = _run_script()
    assert isinstance(result, dict), f"Expected an object from run(), got: {type(result)}"

    state = result.get("mfaFormState")
    assert state is not None, f"mfaFormState missing from result: {result}"

    # explicit assertions on the returned form state
    assert state.get("visible") is True, (
        f"MFA form must be visible, got visible={state.get('visible')} "
        f"(text: {state.get('text')!r})"
    )
    assert isinstance(state.get("top"), (int, float)) and state["top"] >= 0, (
        f"MFA form top must be within the viewport, got top={state.get('top')}"
    )
    text = (state.get("text") or "").lower()
    assert "code" in text, f"MFA form text must mention 'code', got: {state.get('text')!r}"
