"""SV1 - authenticated scan bootstrap.

A scanner that cannot log in only sees the front door. The login form is read
with the same parser as the crawler, its hidden CSRF token is preserved, and
the credentials are sent once through the live HTTP session. The resulting
cookies are the same jar that is later imported into Chromium, so execution
proof happens inside the authenticated session instead of an anonymous copy.

Credentials never appear in a finding, report, checkpoint or console note.
"""

from __future__ import annotations

from dataclasses import dataclass

from . import crawl, identity, net
from .models import Form, FormField

LOGIN_ACTION_HINTS = ("login", "signin", "sign-in", "sign_in", "auth", "session")
USER_HINTS = (
    "username", "user", "email", "login", "account", "identifier",
    "userid", "user_id", "emailaddress",
)
PASSWORD_HINTS = ("password", "passwd", "pwd", "pass")
SKIP_TYPES = ("submit", "button", "image", "reset", "file")
TEXTUAL_TYPES = ("text", "email", "tel", "url", "search", "")


@dataclass
class LoginForm:
    page_url: str
    action: str
    form: Form
    username: FormField
    password: FormField


@dataclass
class LoginResult:
    ok: bool
    note: str
    action: str = ""
    page_url: str = ""
    username_field: str = ""
    password_field: str = ""
    status: int = 0
    redirect: str = ""
    cookies: int = 0
    check: str = ""


def _score_name(name: str, hints: tuple[str, ...]) -> int:
    lowered = (name or "").lower()
    score = 0
    for index, hint in enumerate(hints):
        if lowered == hint:
            score = max(score, 30 - index)
        elif hint in lowered:
            score = max(score, 15 - index)
    return score


def _pick_username(fields: list[FormField], explicit: str) -> FormField | None:
    if explicit:
        for field in fields:
            if field.name == explicit:
                return field
        return None
    candidates = [
        field for field in fields
        if (field.type or "").lower() not in ("hidden", "password")
        and (field.type or "").lower() in TEXTUAL_TYPES
    ]
    if not candidates:
        return None
    return max(
        candidates,
        key=lambda field: (
            _score_name(field.name, USER_HINTS),
            1 if (field.type or "").lower() == "email" else 0,
        ),
    )


def _pick_password(fields: list[FormField], explicit: str) -> FormField | None:
    if explicit:
        for field in fields:
            if field.name == explicit:
                return field
        return None
    candidates = [
        field for field in fields
        if (field.type or "").lower() == "password"
    ]
    if not candidates:
        return None
    return max(
        candidates,
        key=lambda field: _score_name(field.name, PASSWORD_HINTS),
    )


def find_form(page_url: str, html: str, username_field: str = "",
              password_field: str = "") -> tuple[LoginForm | None, str]:
    """Find the most plausible login form in one page.

    A password input is the one non-negotiable signal. The action must be a
    same-origin HTTP(S) endpoint, because the credentials are about to travel
    there and a hostile page must not choose a third-party destination.
    """
    page = crawl.parse_page(page_url, 200, html)
    choices: list[tuple[int, LoginForm]] = []
    for form in page.forms:
        if (form.method or "").lower() != "post":
            continue
        fields = list(form.fields)
        password = _pick_password(fields, password_field)
        if password is None:
            continue
        username = _pick_username(fields, username_field)
        if username is None:
            continue
        action = crawl.form_endpoint(page_url, form)
        if not action or not net.same_origin(action, page_url):
            continue
        score = (
            _score_name(action, LOGIN_ACTION_HINTS)
            + _score_name(form.action or "", LOGIN_ACTION_HINTS)
            + _score_name(username.name, USER_HINTS)
            + _score_name(password.name, PASSWORD_HINTS)
        )
        choices.append((
            score,
            LoginForm(
                page_url=page_url,
                action=action,
                form=form,
                username=username,
                password=password,
            ),
        ))
    if not choices:
        if password_field:
            return None, f"login form without password field '{password_field}'"
        return None, "no same-origin POST login form with a password field"
    choices.sort(key=lambda item: item[0], reverse=True)
    return choices[0][1], ""


def _form_data(login: LoginForm, username: str, password: str) -> list[tuple[str, str]]:
    pairs: list[tuple[str, str]] = []
    for item in login.form.fields:
        kind = (item.type or "").lower()
        if kind in SKIP_TYPES or not item.name:
            continue
        value = item.value or ""
        if item.name == login.username.name:
            value = username
        elif item.name == login.password.name:
            value = password
        pairs.append((item.name, value))
    return pairs


def _cookie_state(client) -> dict[tuple[str, str, str], str]:
    state: dict[tuple[str, str, str], str] = {}
    try:
        cookies = client.cookies
    except AttributeError:
        return state
    for cookie in cookies:
        state[(str(cookie.domain or ""), str(cookie.path or ""), str(cookie.name))] = str(
            cookie.value or ""
        )
    return state


def login(
    client,
    target: str,
    login_url: str = "",
    username: str = "",
    password: str = "",
    username_field: str = "",
    password_field: str = "",
    check: str = "",
) -> LoginResult:
    """Log in through the target's own form and keep the session cookies."""
    if not username or not password:
        return LoginResult(False, "login needs --username and --password")
    login_url = (login_url or target).strip()
    if login_url in ("auto", "target"):
        login_url = target
    if not net.same_origin(login_url, target):
        return LoginResult(False, "login page is outside the target origin")

    page = client.fetch(login_url)
    if not page.ok:
        return LoginResult(False, f"login page unreachable ({page.status or page.error})")
    page_url = page.url or login_url
    if not net.same_origin(page_url, target):
        return LoginResult(False, "login page redirected outside the target origin")

    form, note = find_form(page_url, page.text, username_field, password_field)
    if form is None:
        return LoginResult(False, note, page_url=page_url)

    before = _cookie_state(client)
    data = _form_data(form, username, password)
    multipart = "multipart" in (form.form.enctype or "").lower()
    headers = {"Referer": page_url}
    if multipart:
        files = [(name, (None, value)) for name, value in data]
        response = client.request("POST", form.action, files=files, headers=headers)
    else:
        response = client.request("POST", form.action, data=data, headers=headers)
    if not response.ok:
        return LoginResult(
            False,
            f"login request failed ({response.error or response.status})",
            action=form.action,
            page_url=page_url,
            username_field=form.username.name,
            password_field=form.password.name,
            status=response.status,
        )

    after = _cookie_state(client)
    changed = after != before
    redirect = response.url or form.action
    cookies = len({(domain, name) for domain, _path, name in after})
    detail = f"POST {form.action.split('?', 1)[0]}"

    if response.status >= 400:
        return LoginResult(
            False,
            f"login rejected with status {response.status}",
            action=form.action,
            page_url=page_url,
            username_field=form.username.name,
            password_field=form.password.name,
            status=response.status,
            redirect=redirect,
            cookies=cookies,
        )

    if check:
        confirmed = check in (response.text or "")
        if not confirmed:
            return LoginResult(
                False,
                f"login check string not found after {detail} (status {response.status})",
                action=form.action,
                page_url=page_url,
                username_field=form.username.name,
                password_field=form.password.name,
                status=response.status,
                redirect=redirect,
                cookies=cookies,
                check=check,
            )
        return LoginResult(
            True,
            f"login confirmed by check string; {cookies} cookie(s); {detail}",
            action=form.action,
            page_url=page_url,
            username_field=form.username.name,
            password_field=form.password.name,
            status=response.status,
            redirect=redirect,
            cookies=cookies,
            check=check,
        )

    if changed or identity.normalize_url(redirect) != identity.normalize_url(login_url):
        return LoginResult(
            True,
            f"login accepted; {cookies} cookie(s); {detail}",
            action=form.action,
            page_url=page_url,
            username_field=form.username.name,
            password_field=form.password.name,
            status=response.status,
            redirect=redirect,
            cookies=cookies,
        )

    return LoginResult(
        False,
        "login response looked successful but the session did not change; "
        "pass --login-check STRING to verify",
        action=form.action,
        page_url=page_url,
        username_field=form.username.name,
        password_field=form.password.name,
        status=response.status,
        redirect=redirect,
        cookies=cookies,
    )


def _same_endpoint(first: str, second: str) -> bool:
    """Compare URL paths, ignoring query strings that may hold a CSRF token."""
    left = identity.normalize_url(first).split("?", 1)[0]
    right = identity.normalize_url(second).split("?", 1)[0]
    return bool(left) and left == right


def skip_form(page_url: str, form: Form, action: str) -> bool:
    """True when this form posts to the endpoint used to authenticate."""
    if not action:
        return False
    endpoint = crawl.form_endpoint(page_url, form)
    if not endpoint:
        return False
    return _same_endpoint(endpoint, action)


def skip_point(point, action: str) -> bool:
    """Do not fuzz the credentials that were just used to authenticate.

    Login forms are still crawled and their hidden/visible fields are preserved
    by ordinary form handling. Scanning the username field would turn every
    authenticated run into a credential-stuffing test, so it is opt-in through
    the caller.
    """
    if not action:
        return False
    return (
        point.source in ("form", "multipart")
        and _same_endpoint(point.url, action)
    )
