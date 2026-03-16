import datetime
import json
import os
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

import jwt
import requests
from dotenv import load_dotenv

load_dotenv()

API = "https://api.github.com"
REPO_ROOT = Path(__file__).resolve().parent.parent


@dataclass(frozen=True)
class Config:
    repo: str
    base_branch: str
    reviewer: str | None
    app_id: int
    installation_id: int
    private_key_path: Path


def _require_env(name: str) -> str:
    value = os.getenv(name)
    if not value:
        raise RuntimeError(f"Missing required env var: {name}")
    return value


def run_cmd(
    args: list[str],
    *,
    capture: bool = False,
    check: bool = True,
) -> str | None:
    result = subprocess.run(args, capture_output=capture, text=True)
    if check and result.returncode != 0:
        stderr = (result.stderr or "").strip()
        raise RuntimeError(f"Command failed ({result.returncode}): {args}\n{stderr}")
    return result.stdout.strip() if capture else None


def run_shell(
    cmd: str,
    *,
    capture: bool = False,
    check: bool = True,
) -> str | None:
    result = subprocess.run(cmd, shell=True, capture_output=capture, text=True)
    if check and result.returncode != 0:
        stderr = (result.stderr or "").strip()
        raise RuntimeError(f"Command failed ({result.returncode}): {cmd}\n{stderr}")
    return result.stdout.strip() if capture else None


def git(args: list[str]) -> None:
    run_cmd(["git", *args], check=True)


def load_json(path: Path) -> Any | None:
    if not path.exists():
        return None
    try:
        with path.open(encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


def create_jwt(*, app_id: int, private_key_path: Path) -> str:
    private_key = private_key_path.read_text(encoding="utf-8")
    payload = {
        "iat": int(time.time()) - 60,
        "exp": int(time.time()) + 600,
        # PyJWT expects "iss" to be a string.
        "iss": str(app_id),
    }
    return jwt.encode(
        payload, private_key, algorithm="RS256"
    )  # pyright: ignore[reportUnknownMemberType]


def installation_token(config: Config) -> str:
    jwt_token = create_jwt(app_id=config.app_id, private_key_path=config.private_key_path)
    headers = {
        "Authorization": f"Bearer {jwt_token}",
        "Accept": "application/vnd.github+json",
    }
    url = f"{API}/app/installations/{config.installation_id}/access_tokens"
    r = requests.post(url, headers=headers, timeout=30)
    r.raise_for_status()
    token = r.json().get("token")
    if not isinstance(token, str) or not token:
        raise RuntimeError("GitHub installation token response is missing a token")
    return token


def gh_headers(token: str) -> dict[str, str]:
    return {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }


def gh_request(token: str, method: str, url: str, *, data: dict[str, Any] | None = None) -> Any:
    r = requests.request(method, url, headers=gh_headers(token), json=data, timeout=30)
    try:
        r.raise_for_status()
    except requests.HTTPError as exc:
        body = (r.text or "").strip()
        raise RuntimeError(f"GitHub API error {r.status_code} for {method} {url}: {body}") from exc
    if r.status_code == 204:
        return None
    return r.json()


def git_setup() -> None:
    git(["config", "user.name", "reekeer[bot]"])
    git(["config", "user.email", "reekeer[bot]@users.noreply.github.com"])


def create_branch() -> str:
    ts = datetime.datetime.now(datetime.UTC).strftime("%Y%m%d%H%M%S")
    branch = f"bot/code-quality-{ts}"
    git(["checkout", "-b", branch])
    return branch


def commit_if_changes(message: str) -> bool:
    git(["add", "-A"])
    changed = subprocess.run(["git", "diff", "--cached", "--quiet"])
    if changed.returncode != 0:
        git(["commit", "-m", message])
        return True
    return False


def push(*, token: str, repo: str, branch: str) -> None:
    git(["push", f"https://x-access-token:{token}@github.com/{repo}.git", branch])


def ruff_fix() -> None:
    run_shell("ruff check . --fix", check=False)
    commit_if_changes("style(ruff): auto-fix lint issues")
    run_shell("ruff check . --output-format=json > ruff.json || true", check=False)


def black_fix() -> None:
    run_shell("black .", check=False)
    commit_if_changes("style(black): format code")


def pyright_scan() -> None:
    run_shell("pyright --outputjson > pyright.json || true", check=False)


def _as_dict_list(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    out: list[dict[str, Any]] = []
    for item in cast(list[Any], value):
        if isinstance(item, dict):
            out.append(cast(dict[str, Any], item))
    return out


def ruff_errors() -> list[dict[str, Any]]:
    data = load_json(Path("ruff.json"))
    return _as_dict_list(data)


def pyright_errors() -> list[dict[str, Any]]:
    data = load_json(Path("pyright.json"))
    if not isinstance(data, dict):
        return []
    data_d = cast(dict[str, Any], data)
    diags = data_d.get("generalDiagnostics")
    return _as_dict_list(diags)


def create_pr(*, token: str, repo: str, branch: str, base_branch: str) -> dict[str, Any]:
    url = f"{API}/repos/{repo}/pulls"
    pr = gh_request(
        token,
        "POST",
        url,
        data={
            "title": "chore: automated code quality fixes",
            "head": branch,
            "base": base_branch,
            "body": "Automated fixes from reekeerBot",
        },
    )
    if not isinstance(pr, dict):
        raise RuntimeError("Unexpected response from create PR")
    return cast(dict[str, Any], pr)


def add_reviewer(*, token: str, repo: str, pr_number: int, reviewer: str | None) -> None:
    if not reviewer:
        return
    url = f"{API}/repos/{repo}/pulls/{pr_number}/requested_reviewers"
    gh_request(token, "POST", url, data={"reviewers": [reviewer]})


def comment_pr(*, token: str, repo: str, pr_number: int, text: str) -> None:
    url = f"{API}/repos/{repo}/issues/{pr_number}/comments"
    gh_request(token, "POST", url, data={"body": text})


def pr_head_sha(*, token: str, repo: str, pr_number: int) -> str:
    url = f"{API}/repos/{repo}/pulls/{pr_number}"
    pr = gh_request(token, "GET", url)
    if not isinstance(pr, dict):
        raise RuntimeError("Unexpected response from PR details")
    pr_d = cast(dict[str, Any], pr)
    head = pr_d.get("head")
    if not isinstance(head, dict):
        raise RuntimeError("Unexpected response from PR details (missing head)")
    head_d = cast(dict[str, Any], head)
    sha = head_d.get("sha")
    if not isinstance(sha, str) or not sha:
        raise RuntimeError("Could not read PR head SHA")
    return sha


def _diagnostic_repo_path(file_value: Any) -> str | None:
    if not isinstance(file_value, str) or not file_value:
        return None
    p = Path(file_value)
    if not p.is_absolute():
        p = (REPO_ROOT / p).resolve()
    try:
        rel = p.relative_to(REPO_ROOT)
    except ValueError:
        return None
    return rel.as_posix()


def review_comments(*, token: str, repo: str, pr_number: int, errors: list[dict[str, Any]]) -> None:
    url = f"{API}/repos/{repo}/pulls/{pr_number}/comments"
    commit_sha = pr_head_sha(token=token, repo=repo, pr_number=pr_number)

    posted = 0
    for e in errors:
        if posted >= 30:
            break
        message = e.get("message")
        repo_path = _diagnostic_repo_path(e.get("file"))
        start_line = e.get("range", {}).get("start", {}).get("line")
        if not isinstance(message, str) or not message:
            continue
        if repo_path is None:
            continue
        if not isinstance(start_line, int) or start_line < 0:
            continue

        gh_request(
            token,
            "POST",
            url,
            data={
                "body": f"Pyright error:\n{message}",
                "commit_id": commit_sha,
                "path": repo_path,
                "line": start_line + 1,  # Pyright is 0-based; GitHub is 1-based.
                "side": "RIGHT",
            },
        )
        posted += 1


def auto_merge(*, token: str, repo: str, pr_number: int) -> None:
    url = f"{API}/repos/{repo}/pulls/{pr_number}/merge"
    gh_request(token, "PUT", url)


def summarize(ruff: list[dict[str, Any]], pyright: list[dict[str, Any]]) -> str:
    msg = "# reekeer[bot] Report\n\n"

    if ruff:
        msg += "## Ruff issues\n"
        for r in ruff[:15]:
            filename = r.get("filename")
            loc = r.get("location")
            row = cast(dict[str, Any], loc).get("row") if isinstance(loc, dict) else None
            message = r.get("message")
            if isinstance(filename, str) and isinstance(row, int) and isinstance(message, str):
                msg += f"- {filename}:{row} {message}\n"

    if pyright:
        msg += "\n## Pyright issues\n"
        for p in pyright[:15]:
            file_value = p.get("file")
            message = p.get("message")
            if isinstance(file_value, str) and isinstance(message, str):
                msg += f"- {file_value} {message}\n"

    if not ruff and not pyright:
        msg += "✅ No issues detected"

    return msg


def load_config() -> Config:
    repo = _require_env("GITHUB_REPOSITORY")
    base_branch = os.getenv("BASE_BRANCH", "dev")
    reviewer = os.getenv("REVIEWER") or None
    app_id = int(_require_env("APP_ID"))
    installation_id = int(_require_env("INSTALLATION_ID"))

    private_key_env = os.getenv("PRIVATE_KEY_PATH")
    private_key_path = (
        Path(private_key_env).expanduser() if private_key_env else (REPO_ROOT / "private-key.pem")
    )
    if not private_key_path.is_absolute():
        private_key_path = (REPO_ROOT / private_key_path).resolve()
    if not private_key_path.is_file():
        raise RuntimeError(f"Private key not found: {private_key_path}")

    return Config(
        repo=repo,
        base_branch=base_branch,
        reviewer=reviewer,
        app_id=app_id,
        installation_id=installation_id,
        private_key_path=private_key_path,
    )


def main() -> None:
    config = load_config()
    token = installation_token(config)

    git_setup()
    branch = create_branch()

    ruff_fix()
    black_fix()
    pyright_scan()

    push(token=token, repo=config.repo, branch=branch)

    pr = create_pr(token=token, repo=config.repo, branch=branch, base_branch=config.base_branch)
    pr_number = pr.get("number")
    if not isinstance(pr_number, int):
        raise RuntimeError("Unexpected PR response (missing number)")

    add_reviewer(token=token, repo=config.repo, pr_number=pr_number, reviewer=config.reviewer)

    ruff = ruff_errors()
    pyright = pyright_errors()

    comment_pr(token=token, repo=config.repo, pr_number=pr_number, text=summarize(ruff, pyright))

    if pyright:
        review_comments(token=token, repo=config.repo, pr_number=pr_number, errors=pyright)
    else:
        auto_merge(token=token, repo=config.repo, pr_number=pr_number)


if __name__ == "__main__":
    main()
