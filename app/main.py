import base64, hmac, html, io, json, os, re, secrets, uuid, zipfile
from datetime import datetime, timezone
from ipaddress import IPv4Address, IPv4Network
from pathlib import Path
from urllib.parse import urlsplit

import bleach
import httpx2
from joserfc.errors import JoseError
from argon2.exceptions import InvalidHashError, VerificationError
from bleach.css_sanitizer import CSSSanitizer
from argon2 import PasswordHasher
from authlib.integrations.base_client import OAuthError
from authlib.integrations.starlette_client import OAuth
from fastapi import FastAPI, Request, Form, UploadFile, File, HTTPException
from fastapi.responses import FileResponse, HTMLResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from sqlalchemy import create_engine, func, select, String, Text, Boolean, DateTime, UniqueConstraint, Float, Integer
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker
from starlette.middleware.sessions import SessionMiddleware
from PIL import Image
import tinycss2
import qrcode
import phonenumbers

os.umask(0o077)
DATA = Path(os.getenv("DATA_DIR", "./data")); MEDIA = DATA / "media"
DATA.mkdir(parents=True, exist_ok=True); MEDIA.mkdir(parents=True, exist_ok=True)
engine = create_engine(f"sqlite:///{DATA / 'signatures.db'}", connect_args={"check_same_thread": False})
Session = sessionmaker(engine, expire_on_commit=False)
ph = PasswordHasher()
ADMIN_HASH = os.getenv("ADMIN_PASSWORD_HASH", "") or (ph.hash(os.getenv("ADMIN_PASSWORD", "")) if os.getenv("ADMIN_PASSWORD") else "")
DUMMY_HASH = ph.hash(secrets.token_urlsafe(32))

class Base(DeclarativeBase): pass
class Record(Base):
    __tablename__ = "records"
    id: Mapped[str] = mapped_column(String, primary_key=True)
    kind: Mapped[str] = mapped_column(String, index=True)
    owner_id: Mapped[str | None] = mapped_column(String)
    name: Mapped[str] = mapped_column(String)
    content: Mapped[str] = mapped_column(Text, default="{}")
    source_html: Mapped[str] = mapped_column(Text, default="")
    published: Mapped[bool] = mapped_column(Boolean, default=False)
    published_html: Mapped[str] = mapped_column(Text, default="")
    updated: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))

class ContactProfile(Base):
    __tablename__ = "contact_profiles"
    id: Mapped[str] = mapped_column(String, primary_key=True)
    name: Mapped[str] = mapped_column(String)
    fields: Mapped[str] = mapped_column(Text, default="{}")
    updated: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))


class LocalAdmin(Base):
    __tablename__ = "local_admin"
    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String)
    password_hash: Mapped[str] = mapped_column(Text)
    revision: Mapped[str] = mapped_column(String)


class WorkspaceUser(Base):
    __tablename__ = "workspace_users"
    __table_args__ = (UniqueConstraint("oidc_issuer", "oidc_subject"),)
    id: Mapped[str] = mapped_column(String, primary_key=True)
    username: Mapped[str] = mapped_column(String, unique=True)
    password_hash: Mapped[str] = mapped_column(Text)
    oidc_issuer: Mapped[str | None] = mapped_column(String)
    oidc_subject: Mapped[str | None] = mapped_column(String)
    enabled: Mapped[bool] = mapped_column(Boolean)
    is_admin: Mapped[bool] = mapped_column(Boolean, default=False, server_default="0")
    revision: Mapped[str] = mapped_column(String)


class LoginAttempt(Base):
    __tablename__ = "login_attempts"
    key: Mapped[str] = mapped_column(String, primary_key=True)
    count: Mapped[int] = mapped_column(Integer)
    window_start: Mapped[float] = mapped_column(Float, index=True)


class InstallationSettings(Base):
    __tablename__ = "installation_settings"
    id: Mapped[int] = mapped_column(primary_key=True)
    value: Mapped[str] = mapped_column(Text)
    revision: Mapped[str] = mapped_column(String)


class DirectoryIdentity(Base):
    __tablename__ = "directory_identities"
    namespace: Mapped[str] = mapped_column(String, primary_key=True)
    subject: Mapped[str] = mapped_column(String, primary_key=True)
    user_id: Mapped[str] = mapped_column(String, index=True)


class RevokedOIDCIdentity(Base):
    __tablename__ = "revoked_oidc_identities"
    issuer: Mapped[str] = mapped_column(String, primary_key=True)
    subject: Mapped[str] = mapped_column(String, primary_key=True)


def initialize_database():
    # Take the SQLite write lock before inspecting the schema, including on first startup.
    with engine.begin() as conn:
        conn.exec_driver_sql("BEGIN IMMEDIATE")
        Base.metadata.create_all(conn)
        columns = {row[1] for row in conn.exec_driver_sql("PRAGMA table_info(records)")}
        if "published_html" not in columns:
            conn.exec_driver_sql("ALTER TABLE records ADD COLUMN published_html TEXT NOT NULL DEFAULT ''")
        if "owner_id" not in columns:
            conn.exec_driver_sql("ALTER TABLE records ADD COLUMN owner_id VARCHAR")
        user_columns = {row[1] for row in conn.exec_driver_sql("PRAGMA table_info(workspace_users)")}
        if "is_admin" not in user_columns:
            conn.exec_driver_sql("ALTER TABLE workspace_users ADD COLUMN is_admin BOOLEAN NOT NULL DEFAULT 0")


def check_bind_address(value):
    networks = ("127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
    try:
        address = IPv4Address(value)
    except ValueError:
        raise RuntimeError("SIGNATURE_BIND_IP must be a loopback or private IPv4 address") from None
    if not any(address in IPv4Network(network) for network in networks):
        raise RuntimeError("SIGNATURE_BIND_IP must be a loopback or private IPv4 address")


check_bind_address(os.getenv("SIGNATURE_BIND_IP", "127.0.0.1"))
from .community import Community, persistent_secret
session_secret = os.getenv("SESSION_SECRET", "") or persistent_secret(DATA, ".session-secret")
if len(session_secret) < 32 or session_secret == "replace-with-a-long-random-secret":
    raise RuntimeError("Set SESSION_SECRET to a random secret of at least 32 characters")
if not os.getenv("ADMIN_PASSWORD_HASH") and os.getenv("ADMIN_PASSWORD") == "replace-with-a-unique-strong-password":
    raise RuntimeError("Replace the example administrator password")

initialize_database()
app = FastAPI(title="Make Your Mark by SysAdDad", docs_url=None, redoc_url=None, openapi_url=None)
app.add_middleware(SessionMiddleware, secret_key=session_secret, same_site="lax", https_only=os.getenv("COOKIE_SECURE", "true").lower() == "true")
app.mount("/brand", StaticFiles(directory=Path(__file__).parent / "static" / "brand"), name="brand")

IMAGE_TYPES = {"png": "image/png", "jpg": "image/jpeg", "gif": "image/gif", "webp": "image/webp"}
MEDIA_PATH = re.compile(r"/media/[0-9a-f]{32}\.(png|jpg|gif|webp)")
LOCAL_IMAGE_SRC = re.compile(r'(<img src="|<a href=")(/media/(?:[0-9a-f]{32}\.(?:png|jpg|gif|webp)|social/[a-z]+\.png))"')
SOCIAL_DIR = Path(__file__).parent / "static" / "social"

@app.api_route("/media/{filename}", methods=["GET", "HEAD"])
def media_file(filename: str):
    match = MEDIA_PATH.fullmatch("/media/" + filename)
    path = MEDIA / filename
    if not match or not path.is_file() or path.is_symlink():
        raise HTTPException(404, "Image not found")
    return FileResponse(path, media_type=IMAGE_TYPES[match[1]], headers={"X-Content-Type-Options": "nosniff"})

oauth = OAuth()
oidc_auto_provision = os.getenv("OIDC_AUTO_PROVISION", "").lower() == "true"
issuer = os.getenv("OIDC_ISSUER", "").strip()
oidc_subject = os.getenv("OIDC_ADMIN_SUBJECT", "")
oidc_callback_url = os.getenv("OIDC_REDIRECT_URI", "")
oidc_configured = bool(
    issuer.startswith("https://") and os.getenv("OIDC_CLIENT_ID")
    and oidc_callback_url.startswith("https://")
    and os.getenv("COOKIE_SECURE", "true").lower() == "true"
)
if oidc_configured:
    oauth.register(name="oidc", client_id=os.getenv("OIDC_CLIENT_ID"), client_secret=os.getenv("OIDC_CLIENT_SECRET"), server_metadata_url=issuer.rstrip("/") + "/.well-known/openid-configuration", client_kwargs={"scope": "openid profile email"})

def local_credentials(db):
    admin = db.get(LocalAdmin, 1)
    if admin:
        return admin.username, admin.password_hash, admin.revision
    return os.getenv("ADMIN_USERNAME") or "admin", ADMIN_HASH, ""


def verify_password(password_hash, password):
    try:
        return bool(password_hash) and len(password) <= 4096 and ph.verify(password_hash, password)
    except (VerificationError, InvalidHashError):
        return False


def require_login(request):
    user = request.session.get("user")
    if user and user.get("method") in ("oidc", "ldap"):
        revision = community.auth_revision()
        if request.session.get("auth_revision", "") != revision:
            raise HTTPException(401, "Authentication settings changed. Sign in again.")
    if not user:
        raise HTTPException(401, "Sign in required")
    if user.get("id"):
        with Session() as db:
            editor = db.get(WorkspaceUser, user["id"])
        if not editor or not editor.enabled or editor.revision != request.session.get("editor_revision"):
            raise HTTPException(401, "Your sign-in expired. Sign in again.")
        if user.get("method") == "oidc" and (not oidc_configured or editor.oidc_issuer != issuer):
            raise HTTPException(401, "Your sign-in expired. Sign in again.")
    elif user.get("method") == "local":
        with Session() as db:
            _, _, revision = local_credentials(db)
        if request.session.get("admin_revision", "") != revision:
            raise HTTPException(401, "Your sign-in expired. Sign in again.")
    elif not oidc_configured or user.get("iss") != issuer or not oidc_subject or user.get("sub") != oidc_subject:
        raise HTTPException(401, "Your sign-in expired. Sign in again.")
    return {**user, "is_admin": editor.is_admin if user.get("id") else True}


def require_admin(request):
    if not require_login(request)["is_admin"]:
        raise HTTPException(403, "Administrator access required")

def require_csrf(request):
    token = request.session.get("csrf")
    supplied = request.headers.get("x-csrf-token")
    if not token or not supplied or not hmac.compare_digest(token.encode(), supplied.encode()):
        raise HTTPException(403, "CSRF check failed")

class EmailCSSSanitizer(CSSSanitizer):
    def sanitize_css(self, style):
        declarations = tinycss2.parse_declaration_list(super().sanitize_css(style))
        plain_tokens = {"ident", "whitespace", "number", "dimension", "percentage", "hash", "string", "literal"}
        return tinycss2.serialize([
            declaration for declaration in declarations
            if declaration.type == "declaration"
            and all(token.type in plain_tokens for token in declaration.value)
        ])


CSS = EmailCSSSanitizer(allowed_css_properties={
    "color", "background-color", "font-family", "font-size", "font-weight",
    "font-style", "line-height", "text-align", "text-decoration", "vertical-align",
    "width", "height", "max-width", "padding", "padding-left", "padding-right",
    "padding-top", "padding-bottom", "border", "border-color", "border-style",
    "border-width", "white-space",
})

PLACEHOLDER = re.compile(r"\{\{\s*([a-zA-Z0-9_.-]+)\s*\}\}")
PROFILE_FIELDS = {"name", "title", "company", "email", "phone", "website", "address"}
MAX_HTML_BYTES = 500_000


def interpolate(value, fields):
    return PLACEHOLDER.sub(lambda m: str(fields.get(m.group(1), "")), str(value or ""))


def safe_url(raw, schemes):
    if re.search(r"[\x00-\x20\x7f\\]", raw):
        return ""
    try:
        parsed = urlsplit(raw)
        if parsed.scheme == "https" and "https" in schemes:
            return raw if parsed.hostname and not parsed.username and not parsed.password and "@" not in parsed.netloc else ""
        if parsed.scheme in schemes and parsed.scheme in {"mailto", "tel"} and parsed.path and not parsed.netloc:
            return raw
    except ValueError:
        pass
    return ""


def import_attribute(tag, name, value):
    if tag == "a" and name == "href":
        return bool(safe_url(value, {"https", "mailto", "tel"}))
    if tag == "img" and name == "src":
        return bool(safe_url(value, {"https"}) or MEDIA_PATH.fullmatch(value))
    return name in {"style", "width", "height", "align", "valign", "cellpadding", "cellspacing",
                    "border", "bgcolor", "color", "face", "size"} or (
        tag == "img" and name == "alt" or tag == "a" and name == "title"
    )


def clean_markup(markup):
    return bleach.clean(
        markup,
        tags=["table", "tbody", "thead", "tr", "td", "th", "div", "span", "p", "br", "b",
              "strong", "i", "em", "u", "a", "img", "hr", "font"],
        attributes=import_attribute, protocols=["https", "mailto", "tel"], css_sanitizer=CSS,
        strip=True,
    )


def render_size(value, default, minimum, maximum):
    try:
        return max(minimum, min(maximum, int(value)))
    except (ValueError, TypeError, OverflowError):
        return default


SOCIAL_PLATFORMS = {
    "facebook": "Facebook", "instagram": "Instagram", "x": "X", "youtube": "YouTube",
    "reddit": "Reddit", "linkedin": "LinkedIn", "tiktok": "TikTok", "threads": "Threads",
    "github": "GitHub", "pinterest": "Pinterest", "mastodon": "Mastodon", "bluesky": "Bluesky",
}
MAX_COLUMNS = 6
LINK_TYPES = ("link", "email", "phone")
ALIGNMENTS = ("left", "center", "right")
VERTICAL_ALIGNMENTS = ("top", "middle", "bottom")
FONT_STACKS = {
    "Arial": "Arial,sans-serif",
    "Calibri": "Calibri,Arial,sans-serif",
    "Helvetica": "Helvetica,Arial,sans-serif",
    "Verdana": "Verdana,Geneva,sans-serif",
    "Tahoma": "Tahoma,Arial,sans-serif",
    "Trebuchet MS": "Trebuchet MS,Arial,sans-serif",
    "Georgia": "Georgia,Times New Roman,serif",
    "Times New Roman": "Times New Roman,Times,serif",
    "Courier New": "Courier New,Courier,monospace",
}
FONT_NAME = re.compile(r"[\w .-]{1,80}")


@app.api_route("/media/social/{platform}.png", methods=["GET", "HEAD"])
def social_icon(platform: str):
    if platform not in SOCIAL_PLATFORMS:
        raise HTTPException(404, "Image not found")
    return FileResponse(SOCIAL_DIR / f"{platform}.png", media_type="image/png",
                        headers={"X-Content-Type-Options": "nosniff"})


def local_asset_path(url):
    base = public_base()
    path = url.removeprefix(base) if base else url
    return path if MEDIA_PATH.fullmatch(path) else ""


def alignment(value, default="left"):
    return value if value in ALIGNMENTS else default


def font_stack(value, default=FONT_STACKS["Arial"]):
    if not isinstance(value, str) or not FONT_NAME.fullmatch(value.strip()):
        return default
    name = value.strip()
    return FONT_STACKS.get(name, f"'{name}',Arial,sans-serif")


def email_table(rows, align=None):
    position = f' align="{align}"' if align else ""
    return (f'<table role="presentation" cellpadding="0" cellspacing="0" border="0"{position} '
            f'style="border-collapse:collapse"><tbody>{rows}</tbody></table>')


def render_rows(blocks, fields, inherited="left", *, font=FONT_STACKS["Arial"],
                asset_origin=None, allow_sections=True):
    origin = public_base() if asset_origin is None else asset_origin
    rows = []
    for block in blocks if isinstance(blocks, list) else []:
        if not isinstance(block, dict) or block.get("hidden"):
            continue
        kind = block.get("type", "text")
        align = alignment(block.get("align"), inherited)
        if kind == "section":
            if not allow_sections:
                continue
            columns = block.get("columns")
            if not isinstance(columns, list):
                continue
            rendered = [render_rows(col, fields, align, font=font, asset_origin=asset_origin,
                                    allow_sections=False) for col in columns[:MAX_COLUMNS]]
            widths = block.get("column_widths")
            widths = widths if isinstance(widths, list) else []
            vertical = block.get("column_vertical_align")
            vertical = vertical if isinstance(vertical, list) else []
            cells = []
            for index, column in enumerate(rendered):
                if not column:
                    continue
                width = render_size(widths[index], 0, 0, 600) if index < len(widths) else 0
                position = vertical[index] if index < len(vertical) else "top"
                position = position if position in VERTICAL_ALIGNMENTS else "top"
                sizing = f' width="{width}"' if width else ""
                style = f"width:{width}px" if width else ""
                if position != "top":
                    style = ";".join(filter(None, (style, f"vertical-align:{position}")))
                if style:
                    sizing += f' style="{style}"'
                cells.append(f'<td valign="{position}"{sizing}>{email_table(column)}</td>')
            if cells:
                space = render_size(block.get("column_gap"), 12, 0, 80)
                gap = f'<td width="{space}" style="width:{space}px;font-size:1px">&nbsp;</td>' if space else ""
                rows.append(f'<tr><td align="{align}">{email_table("<tr>" + gap.join(cells) + "</tr>")}</td></tr>')
            continue
        size = render_size(block.get("font_size"), 14, 8, 36)
        color = str(block.get("color", "#222222"))
        if not re.fullmatch(r"#[0-9a-fA-F]{6}", color):
            color = "#222222"
        weight = "bold" if block.get("bold") else "normal"
        italic = "italic" if block.get("italic") else "normal"
        family = font_stack(block.get("font"), font)
        pixels = render_size(block.get("line_height"), 0, 0, 80)
        line_height = f"{pixels}px" if pixels else "1.4"
        style = (f"font-family:{family};font-size:{size}px;line-height:{line_height};color:{color};"
                 f"font-weight:{weight};font-style:{italic};text-align:{align};")
        padding = 2
        value = html.escape(interpolate(block.get("text"), fields), quote=True)
        value = re.sub(r"\r\n|[\r\n]", "<br>", value)
        if kind == "image":
            url = interpolate(block.get("url"), fields).strip()
            path = local_asset_path(url)
            if path:
                url = origin + path
            elif not safe_url(url, {"https"}):
                continue
            alt = html.escape(interpolate(block.get("alt"), fields), quote=True)
            contact_qr = block.get("contact_qr") is True
            width = render_size(block.get("width"), 100 if contact_qr else 120, 1, 100 if contact_qr else 600)
            value = (f'<img src="{html.escape(url, quote=True)}" alt="{alt}" width="{width}" '
                     f'style="display:inline-block;border:0;width:{width}px;height:auto">')
            if contact_qr:
                value = f'<a href="{html.escape(url, quote=True)}">{value}</a>'
            padding = 4
        elif kind == "divider":
            value = '<hr style="border:0;border-top:1px solid #bbb">'
            padding = 5
        elif kind == "spacer":
            # Keep the height on the cell. Safari can enlarge the text line in a nested spacer.
            rows.append('<tr><td height="12" style="height:12px;font-size:0;line-height:0">&nbsp;</td></tr>')
            continue
        elif kind in LINK_TYPES:
            href, destination = block_link(block, fields)
            if kind != "link" and not value.strip():
                value = html.escape(destination, quote=True)
            if href:
                value = email_link(href, value, block.get("link_color"), block.get("underline", True))
        elif kind == "social":
            links = []
            for platform, url in block.get("links", {}).items():
                href = safe_url(interpolate(url, fields).strip(), {"https"})
                if platform in SOCIAL_PLATFORMS and href:
                    label = SOCIAL_PLATFORMS[platform]
                    if origin or asset_origin is not None:
                        src = html.escape(f"{origin}/media/social/{platform}.png", quote=True)
                        label = (f'<img src="{src}" width="24" height="24" alt="{label}" '
                                 'style="display:inline-block;width:24px;height:24px;border:0;vertical-align:middle">')
                    links.append(email_link(href, label))
            if not links:
                continue
            separator = "&nbsp;&nbsp;" if origin or asset_origin is not None else " &middot; "
            value = separator.join(links)
        top = render_size(block.get("padding_top"), padding, 0, 80)
        bottom = render_size(block.get("padding_bottom"), padding, 0, 80)
        rows.append(f'<tr><td align="{align}" style="{style}padding:{top}px 0 {bottom}px">{value}</td></tr>')
    return "".join(rows)


def block_link(block, fields):
    kind = block.get("type")
    target = interpolate(block.get("href"), fields).strip()
    if kind == "email":
        address = re.sub(r"^mailto:", "", target, flags=re.I).strip()
        valid = re.fullmatch(r"[A-Za-z0-9.!$'*+/=^_`{|}~-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+", address)
        return ("mailto:" + address if valid else ""), address
    if kind == "phone":
        number = re.sub(r"^tel:", "", target, flags=re.I).strip()
        region = block.get("country_region")
        if region in phonenumbers.SUPPORTED_REGIONS and re.fullmatch(r"\+?[0-9 ().-]+", number):
            try:
                parsed = phonenumbers.parse(number, region)
            except phonenumbers.NumberParseException:
                return "", number
            if phonenumbers.is_possible_number(parsed):
                return (
                    "tel:" + phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164),
                    phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.NATIONAL),
                )
            return "", number
        dialable = re.sub(r"^(\+[1-9][0-9]{0,2}[\s.-]*)\(0\)", r"\1", number)
        compact = re.sub(r"[\s().-]", "", dialable)
        if not compact.startswith("+"):
            code = interpolate(block.get("country_code"), fields).strip().removeprefix("+")
            if not re.fullmatch(r"[1-9][0-9]{0,2}", code):
                return "", number
            compact = "+" + code + compact
        match = re.fullmatch(r"\+1([0-9]{3})([0-9]{3})([0-9]{4})", compact)
        if match:
            area, prefix, subscriber = match.groups()
            number = f"({area}) {prefix}-{subscriber}"
        return ("tel:" + compact if re.fullmatch(r"\+[1-9][0-9]{6,14}", compact) else ""), number
    return website_url(target, {"https", "mailto", "tel"}), target


def website_url(target, schemes):
    if re.fullmatch(r"(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}(?::[0-9]+)?(?:[/?#].*)?", target):
        target = "https://" + target
    return safe_url(target, schemes)


def email_link(href, label, color=None, underline=True):
    color = color if isinstance(color, str) and re.fullmatch(r"#[0-9a-fA-F]{6}", color) else "#1266a5"
    decoration = "underline" if underline else "none"
    return f'<a href="{html.escape(href, quote=True)}" style="color:{color};text-decoration:{decoration}">{label}</a>'


def render_blocks(doc, fields=None, *, asset_origin=None):
    align = alignment(doc.get("align"))
    rows = render_rows(doc.get("blocks"), fields or {}, align, font=font_stack(doc.get("font")),
                       asset_origin=asset_origin)
    rows = rows or '<tr><td style="font:14px Arial,sans-serif">New signature</td></tr>'
    return email_table(rows, align if align != "left" else None)

@app.get("/health")
def health(): return {"status":"ok"}

@app.get("/", response_class=HTMLResponse)
def home(request: Request):
    try:
        require_login(request)
    except HTTPException:
        return RedirectResponse("/login")
    token=request.session.setdefault("csrf", secrets.token_urlsafe(32))
    page=(Path(__file__).parent / "static" / "index.html").read_text()
    fonts = "".join(f'<option value="{html.escape(name, quote=True)}"></option>' for name in FONT_STACKS)
    calling_codes = {region: phonenumbers.country_code_for_region(region)
                     for region in sorted(phonenumbers.SUPPORTED_REGIONS)}
    return HTMLResponse(community.brand(page).replace("__CSRF__", token)
                        .replace("__EDITOR_SCRIPT_TYPE__", "text/javascript")
                        .replace("__SOCIAL_PLATFORMS__", json.dumps(SOCIAL_PLATFORMS))
                        .replace("__MAX_COLUMNS__", str(MAX_COLUMNS))
                        .replace("__FONT_OPTIONS__", fonts)
                        .replace("__CALLING_CODES__", json.dumps(calling_codes)))

@app.get("/login", response_class=HTMLResponse)
def login_page():
    if community.setup_needed():
        return RedirectResponse("/setup", status_code=303)
    oidc_origin = urlsplit(oidc_callback_url)
    oidc_url = oidc_origin.scheme + "://" + oidc_origin.netloc + "/auth/oidc"
    oidc = f'<p><a href="{html.escape(oidc_url, quote=True)}">Sign in with SSO</a></p>' if oidc_configured else ""
    page = (Path(__file__).parent / "static" / "login.html").read_text()
    directory = '<label>Sign-in method<select name="method"><option value="local">Local account</option><option value="ldap">Directory account</option></select></label>' if community.settings()[0]['ldap_enabled'] else ''
    return HTMLResponse(community.brand(page).replace("__OIDC_LOGIN__", oidc).replace("__DIRECTORY_LOGIN__", directory))

@app.post("/login")
def login(request: Request, username: str=Form(...), password: str=Form(...), method: str=Form("local")):
    if community.setup_needed():
        raise HTTPException(403, "Complete installation setup first")
    origin = request.headers.get("origin")
    if origin and (urlsplit(origin).netloc != request.url.netloc or urlsplit(origin).scheme not in ("http", "https")):
        raise HTTPException(403, "Sign in from this app's own login page")
    community.rate_limit(request)
    username = checked_username(username)
    if method == "ldap":
        return community.directory_login(request, username, password)
    if method != "local":
        raise HTTPException(400, "Choose a supported sign-in method")
    with Session() as db:
        expected_user, password_hash, revision = local_credentials(db)
        is_owner = hmac.compare_digest(username.encode(), expected_user.encode())
        editor = None if is_owner else find_editor(db, username)
    if not is_owner:
        password_hash = editor.password_hash if editor and editor.enabled else ""
    if not verify_password(password_hash or DUMMY_HASH, password) or not password_hash:
        raise HTTPException(401, "Invalid credentials")
    start_session(request, username, "local", editor=editor)
    if is_owner:
        request.session["admin_revision"] = revision
    return RedirectResponse("/", status_code=303)

@app.post("/logout")
async def logout(request: Request):
    require_login(request)
    form=await request.form()
    if not request.session.get("csrf") or not hmac.compare_digest(request.session["csrf"].encode(), str(form.get("csrf", "")).encode()): raise HTTPException(403,"CSRF check failed")
    request.session.clear(); return RedirectResponse("/login",status_code=303)

@app.get("/auth/oidc")
async def oidc_login(request: Request):
    community.rate_limit(request)
    client = oauth.create_client("oidc")
    if not client:
        raise HTTPException(503, "OIDC is not configured")
    canonical = urlsplit(oidc_callback_url)
    if request.url.netloc != canonical.netloc:
        return RedirectResponse(canonical.scheme + "://" + canonical.netloc + "/auth/oidc", status_code=303)
    request.session['auth_revision'] = community.auth_revision()
    return await client.authorize_redirect(request, oidc_callback_url)

@app.get("/auth/oidc/callback")
async def oidc_callback(request: Request):
    client = oauth.create_client("oidc")
    if not client:
        raise HTTPException(503, "OIDC is not configured")
    auth_revision = community.auth_revision()
    if request.session.get('auth_revision', '') != auth_revision:
        raise HTTPException(401, "Authentication settings changed. Start sign-in again.")
    try:
        token = await client.authorize_access_token(request)
    except (OAuthError, JoseError, httpx2.HTTPError, KeyError, ValueError, TypeError) as error:
        category = getattr(error, "error", "")
        allowed = {"mismatching_state", "invalid_client", "invalid_grant", "access_denied"}
        category = category if category in allowed else "verification_failed"
        print(f"OIDC verification failed ({category}; {type(error).__name__})", flush=True)
        detail = "Single sign-on could not be verified"
        if category == "mismatching_state":
            detail = "Your sign-in session expired or its cookie is missing. Start again from the HTTPS login page in the same browser tab."
        raise HTTPException(401, detail) from None
    if community.auth_revision() != auth_revision:
        raise HTTPException(401, "Authentication settings changed. Start sign-in again.")
    claims = token.get("userinfo")
    subject = claims.get("sub") if claims else None
    if not isinstance(subject, str) or not subject or claims.get("iss") != issuer:
        raise HTTPException(403, "OIDC identity is not authorized")
    editor = None
    if subject != oidc_subject:
        with Session() as db:
            if oidc_auto_provision:
                db.connection().exec_driver_sql("BEGIN IMMEDIATE")
            editor = db.scalar(select(WorkspaceUser).where(
                WorkspaceUser.oidc_issuer == issuer, WorkspaceUser.oidc_subject == subject,
            ))
            if not editor and oidc_auto_provision and not db.get(RevokedOIDCIdentity, (issuer, subject)):
                username = claims.get("preferred_username") or claims.get("email") or "sso-user"
                if not isinstance(username, str) or not username.strip().isprintable():
                    username = "sso-user"
                username = username.strip()[:120]
                owner_name = local_credentials(db)[0]
                base = username[:111]
                while username == owner_name or find_editor(db, username):
                    username = f"{base}-{secrets.token_hex(4)}"
                editor = WorkspaceUser(
                    id=uuid.uuid4().hex, username=username, password_hash="",
                    oidc_issuer=issuer, oidc_subject=subject, enabled=True, is_admin=False,
                    revision=secrets.token_urlsafe(24),
                )
                db.add(editor)
                db.commit()
        if not editor or not editor.enabled:
            raise HTTPException(403, "OIDC identity is not authorized")
    start_session(request, editor.username if editor else claims.get("email") or subject, "oidc", editor=editor)
    request.session["user"].update(iss=issuer, sub=subject)
    request.session["auth_revision"] = auth_revision
    return RedirectResponse("/",status_code=303)


def find_editor(db, username):
    return db.scalar(select(WorkspaceUser).where(WorkspaceUser.username == username))


def start_session(request, username, method, *, editor=None):
    request.session.clear()
    request.session["user"] = {"name": username, "method": method}
    request.session["csrf"] = secrets.token_urlsafe(32)
    if editor:
        request.session["user"]["id"] = editor.id
        request.session["editor_revision"] = editor.revision


@app.get("/api/session")
def session_info(request: Request):
    user = require_login(request)
    return {"user": user, "csrf": request.session["csrf"], "can_manage_users": user["is_admin"]}


@app.get("/api/account")
def account(request: Request):
    user = require_login(request)
    with Session() as db:
        if user.get("id"):
            editor = db.get(WorkspaceUser, user["id"])
            username, password_hash = editor.username, editor.password_hash
        else:
            username, password_hash, _ = local_credentials(db)
    return {"username": username, "local_login_enabled": bool(password_hash),
            "signed_in_as": username if user.get("id") or user.get("method") == "local" else user["name"],
            "role": "admin" if user["is_admin"] else "member",
            "sign_in_method": user["method"]}


@app.post("/api/account")
def update_account(
    request: Request,
    username: str = Form(...),
    current_password: str = Form(...),
    new_password: str = Form(""),
):
    user = require_login(request)
    require_csrf(request)
    username = checked_username(username)
    check_new_password(new_password)
    editor_id = user.get("id")
    with Session() as db:
        if editor_id:
            editor = db.get(WorkspaceUser, editor_id)
            if not editor or not editor.enabled or editor.revision != request.session.get("editor_revision"):
                raise HTTPException(401, "Your sign-in expired. Sign in again.")
            old_username, password_hash, revision = editor.username, editor.password_hash, editor.revision
        else:
            old_username, password_hash, revision = local_credentials(db)
    if not verify_password(password_hash, current_password):
        raise HTTPException(403, "The current password is incorrect")
    if username == old_username and not new_password:
        return {"username": username}
    replacement = ph.hash(new_password) if new_password else password_hash
    new_revision = secrets.token_urlsafe(24)
    with Session() as db:
        db.connection().exec_driver_sql("BEGIN IMMEDIATE")
        editor = db.get(WorkspaceUser, editor_id) if editor_id else None
        owner_name, _, owner_revision = local_credentials(db)
        if (editor_id and not editor) or (editor.revision if editor else owner_revision) != revision:
            raise HTTPException(409, "Account settings changed elsewhere. Reopen settings and try again.")
        taken = find_editor(db, username)
        if (taken and taken.id != editor_id) or (editor and username == owner_name):
            raise HTTPException(409, "That username is already in use")
        if editor:
            editor.username, editor.password_hash, editor.revision = username, replacement, new_revision
        else:
            db.merge(LocalAdmin(id=1, username=username, password_hash=replacement, revision=new_revision))
        db.commit()

    if editor_id:
        request.session["user"]["name"] = username
        request.session["editor_revision"] = new_revision
    elif user.get("method") == "local":
        request.session["user"]["name"] = username
        request.session["admin_revision"] = new_revision
    return {"username": username}


def checked_username(username):
    username = username.strip()
    if not 1 <= len(username) <= 120 or not username.isprintable():
        raise HTTPException(400, "Enter a username of up to 120 characters")
    return username


def check_new_password(password):
    if password and (not 12 <= len(password) <= 1024 or not password.strip()):
        raise HTTPException(400, "Enter a new password between 12 and 1024 characters")


def user_details(user):
    return {
        "id": user.id, "username": user.username, "enabled": user.enabled,
        "is_admin": user.is_admin,
        "local_login_enabled": bool(user.password_hash),
        "oidc_subject": user.oidc_subject or "",
        "oidc_issuer": user.oidc_issuer or "",
        "directory_login_enabled": directory_identity_exists(user.id),
    }


@app.get("/api/users")
def workspace_users(request: Request):
    require_admin(request)
    with Session() as db:
        username, password_hash, _ = local_credentials(db)
        editors = db.scalars(select(WorkspaceUser).order_by(WorkspaceUser.username))
        return {
            "owner": {
                "username": username,
                "local_login_enabled": bool(password_hash),
                "oidc_login_enabled": bool(oidc_configured and oidc_subject),
            },
            "users": [user_details(editor) for editor in editors],
            "oidc_configured": oidc_configured,
        }


@app.delete("/api/users/{user_id}", status_code=204)
def delete_workspace_user(request: Request, user_id: str):
    require_admin(request)
    require_csrf(request)
    with Session() as db:
        db.connection().exec_driver_sql("BEGIN IMMEDIATE")
        editor = db.get(WorkspaceUser, user_id)
        if not editor:
            raise HTTPException(404, "Editor not found")
        if editor.oidc_issuer and editor.oidc_subject:
            db.merge(RevokedOIDCIdentity(issuer=editor.oidc_issuer, subject=editor.oidc_subject))
        db.delete(editor)
        db.commit()
    return Response(status_code=204)


@app.post("/api/users")
def save_workspace_user(
    request: Request,
    username: str = Form(...),
    user_id: str = Form(""),
    password: str = Form(""),
    subject: str = Form(""),
    enabled: bool = Form(True),
    remove_local_password: bool = Form(False),
    is_admin: bool | None = Form(None),
):
    require_admin(request)
    require_csrf(request)
    username = checked_username(username)
    check_new_password(password)
    if subject and (len(subject) > 255 or not subject.isascii() or any(not 33 <= ord(c) <= 126 for c in subject)):
        raise HTTPException(400, "Enter the exact OIDC subject from your provider")
    if password and remove_local_password:
        raise HTTPException(400, "Choose a new password or remove the password")
    new_hash = ph.hash(password) if password else ""
    with Session() as db:
        db.connection().exec_driver_sql("BEGIN IMMEDIATE")
        editor = db.get(WorkspaceUser, user_id) if user_id else None
        if user_id and not editor:
            raise HTTPException(404, "User not found")
        taken = find_editor(db, username)
        if username == local_credentials(db)[0] or (taken and taken.id != user_id):
            raise HTTPException(409, "That username is already in use")
        if subject and not oidc_configured and (not editor or subject != editor.oidc_subject):
            raise HTTPException(400, "Configure HTTPS OIDC before assigning a subject")
        subject_issuer = None
        if subject:
            subject_issuer = editor.oidc_issuer if editor and subject == editor.oidc_subject else issuer
        if subject:
            assigned = db.scalar(select(WorkspaceUser).where(
                WorkspaceUser.oidc_issuer == subject_issuer, WorkspaceUser.oidc_subject == subject,
            ))
            if subject == oidc_subject or (assigned and assigned.id != user_id):
                raise HTTPException(409, "That OIDC identity is already assigned")
        password_hash = new_hash or (editor.password_hash if editor and not remove_local_password else "")
        if enabled and not (password_hash or subject or (editor and directory_identity_exists(editor.id))):
            raise HTTPException(400, "An enabled user needs a local password or an OIDC subject")
        if not editor:
            editor = WorkspaceUser(id=uuid.uuid4().hex)
            db.add(editor)
        editor.username = username
        editor.password_hash = password_hash
        if editor.oidc_issuer and editor.oidc_subject and (editor.oidc_issuer, editor.oidc_subject) != (subject_issuer, subject):
            db.merge(RevokedOIDCIdentity(issuer=editor.oidc_issuer, subject=editor.oidc_subject))
        editor.oidc_issuer = subject_issuer
        editor.oidc_subject = subject or None
        editor.enabled = enabled
        if is_admin is not None:
            editor.is_admin = is_admin
        editor.revision = secrets.token_urlsafe(24)
        db.commit()
        return user_details(editor)


async def json_object(request):
    try:
        data = await request.json()
    except (ValueError, UnicodeError):
        raise HTTPException(400, "Invalid JSON")
    if not isinstance(data, dict):
        raise HTTPException(400, "Expected a JSON object")
    return data


def optional_id(value):
    if value is not None and (not isinstance(value, str) or len(value) > 120):
        raise HTTPException(400, "Invalid record or profile ID")
    return value or None


def validated_content(content):
    if not isinstance(content, dict):
        raise HTTPException(400, "Content must be an object")
    optional_id(content.get("profile_id"))
    validate_font(content.get("font", ""))
    blocks = content.get("blocks", [])
    if not isinstance(blocks, list) or len(blocks) > 200:
        raise HTTPException(400, "Provide up to 200 blocks")
    total = len(blocks)
    for block in blocks:
        validate_block(block, allow_section=True)
        if block.get("type") == "section":
            for column in block["columns"]:
                total += len(column)
                if total > 200:
                    raise HTTPException(400, "Provide up to 200 blocks")
                for child in column:
                    validate_block(child)
    return content


def validate_font(value):
    if not isinstance(value, str) or len(value) > 80 or (value.strip() and not FONT_NAME.fullmatch(value.strip())):
        raise HTTPException(400, "Use a font name of up to 80 letters, numbers, spaces, periods, underscores, or hyphens")


def validate_block(block, *, allow_section=False):
    if not isinstance(block, dict):
        raise HTTPException(400, "Invalid block")
    kind = block.get("type", "text")
    if kind == "section" and allow_section:
        columns = block.get("columns")
        if not isinstance(columns, list) or not 1 <= len(columns) <= MAX_COLUMNS or not all(isinstance(col, list) for col in columns):
            raise HTTPException(400, f"A row must contain between 1 and {MAX_COLUMNS} columns")
        widths = block.get("column_widths", [])
        if not isinstance(widths, list) or len(widths) > len(columns) or any(
            width is not None and (type(width) is not int or not 1 <= width <= 600) for width in widths
        ):
            raise HTTPException(400, "Column widths must be Auto or between 1 and 600 pixels")
        vertical = block.get("column_vertical_align", [])
        if not isinstance(vertical, list) or len(vertical) > len(columns) or any(
            position not in VERTICAL_ALIGNMENTS for position in vertical
        ):
            raise HTTPException(400, "Column vertical alignment must be Top, Middle, or Bottom")
    elif kind not in ("text", "image", "divider", "spacer", "social", *LINK_TYPES):
        raise HTTPException(400, "Invalid block type")
    for key in ("text", "href", "url", "alt", "color", "align", "country_code", "country_region", "link_color"):
        if key in block and (not isinstance(block[key], str) or len(block[key]) > 8192):
            raise HTTPException(400, f"Invalid block field: {key}")
    for key in ("column_gap", "padding_top", "padding_bottom", "line_height"):
        value = block.get(key)
        if key in block and (type(value) is not int or not 0 <= value <= 80):
            raise HTTPException(400, f"{key.replace('_', ' ').capitalize()} must be between 0 and 80 pixels")
    validate_font(block.get("font", ""))
    if kind == "social":
        links = block.get("links", {})
        if not isinstance(links, dict) or any(
            key not in SOCIAL_PLATFORMS or not isinstance(url, str) or len(url) > 8192
            for key, url in links.items()
        ):
            raise HTTPException(400, "Invalid social links")


def profile_values(db, content, *, require_existing=False):
    profile_id = optional_id(content.get("profile_id"))
    if not profile_id:
        return {}
    profile = db.get(ContactProfile, profile_id)
    if not profile and require_existing:
        raise HTTPException(400, "The selected contact profile no longer exists")
    return json.loads(profile.fields) if profile else {}


def checked_source(raw):
    if not isinstance(raw, str):
        raise HTTPException(400, "HTML source must be text")
    try:
        size = len(raw.encode("utf-8"))
    except UnicodeError:
        raise HTTPException(400, "HTML source must be valid UTF-8")
    if size > MAX_HTML_BYTES:
        raise HTTPException(413, "HTML exceeds 500 KB")
    return raw


def public_base():
    base = os.getenv("PUBLIC_BASE_URL", "").rstrip("/")
    if not safe_url(base, {"https"}):
        return ""
    parsed = urlsplit(base)
    return base if not (parsed.path or parsed.query or parsed.fragment) else ""


def publish_snapshot(content, fields, *, for_email=False):
    visible = []
    for block in content.get("blocks", []):
        if block.get("hidden"):
            continue
        if block.get("type") == "section":
            visible.extend(child for column in block["columns"] for child in column if not child.get("hidden"))
        else:
            visible.append(block)
    if not visible:
        raise HTTPException(400, "Add a visible editor block before publishing")
    for block in visible:
        if block.get("type") in ("email", "phone") and not block_link(block, fields)[0]:
            kind = block["type"]
            detail = "Enter a valid email address" if kind == "email" else "Enter a phone number with a country calling code"
            raise HTTPException(400, detail + " before publishing.")
        if block.get("type") == "link" and interpolate(block.get("href"), fields).strip() and not block_link(block, fields)[0]:
            raise HTTPException(400, "Enter a valid website URL before exporting or saving a version.")
        if block.get("type") == "image":
            url = interpolate(block.get("url"), fields).strip()
            path = local_asset_path(url)
            if path and for_email and not public_base():
                label = interpolate(block.get("alt"), fields).strip()[:80] or "Uploaded image"
                raise HTTPException(400, f"“{label}” is stored on the LAN. Download HTML and images, or use a public HTTPS image origin to copy it for email.")
            if path and not (MEDIA / path.rsplit("/", 1)[1]).is_file():
                raise HTTPException(400, "An image is missing. Upload it again.")
            if not safe_url(url, {"https"}) and not path:
                raise HTTPException(400, "Add a valid HTTPS image URL or upload an image before publishing.")
        if block.get("type") == "social":
            for platform, value in block.get("links", {}).items():
                url = interpolate(value, fields).strip()
                if value.strip() and not safe_url(url, {"https"}):
                    raise HTTPException(400, f"{SOCIAL_PLATFORMS[platform]} requires an HTTPS URL")
    if not render_rows(content.get("blocks", []), fields, alignment(content.get("align"))):
        raise HTTPException(400, "Add a visible editor block before publishing")
    return render_blocks(content, fields, asset_origin=None if for_email else public_base())


def template_content(content):
    def without_qr(blocks):
        return [
            {**block, "columns": [without_qr(column) for column in block["columns"]]}
            if block.get("type") == "section" else block
            for block in blocks if not block.get("contact_qr")
        ]

    result = {**content, "blocks": without_qr(content.get("blocks", []))}
    if isinstance(content.get("guided"), dict):
        result["guided"] = {**content["guided"], "qrUrl": ""}
    return result


@app.get("/api/records")
def records(request: Request):
    user = require_login(request)
    with Session() as db:
        query = select(Record).order_by(Record.updated.desc())
        if not user["is_admin"]:
            query = query.where((Record.kind == "template") | (Record.owner_id == user["id"]))
        return [{"id": r.id, "kind": r.kind, "name": r.name, "content": template_content(json.loads(r.content)) if r.kind == "template" else json.loads(r.content),
                 "source_html": r.source_html, "published": r.published,
                 "has_snapshot": bool(r.published_html), "updated": r.updated.isoformat(),
                 "can_edit": user["is_admin"] or r.owner_id == user.get("id")}
                for r in db.scalars(query)]


def readable_record(db, record_id, user):
    record = db.get(Record, record_id)
    if not record or (
        not user["is_admin"] and record.kind != "template" and record.owner_id != user["id"]
    ):
        raise HTTPException(404, "Record not found")
    return record


@app.get("/api/profiles")
def profiles(request: Request):
    require_login(request)
    with Session() as db:
        return [{"id": p.id, "name": p.name, "fields": json.loads(p.fields)}
                for p in db.query(ContactProfile).order_by(ContactProfile.name).all()]


@app.post("/api/profiles")
async def save_profile(request: Request):
    require_admin(request)
    require_csrf(request)
    data = await json_object(request)
    name = data.get("name")
    fields = data.get("fields", {})
    if not isinstance(name, str) or not name.strip() or len(name.strip()) > 120:
        raise HTTPException(400, "Enter a profile name of up to 120 characters")
    if not isinstance(fields, dict) or any(
        k not in PROFILE_FIELDS or not isinstance(v, str) or len(v) > 500
        for k, v in fields.items()
    ):
        raise HTTPException(400, "Profile fields must be supported text values up to 500 characters")
    existing_id = optional_id(data.get("id"))
    profile_id = existing_id or str(uuid.uuid4())
    with Session() as db:
        if existing_id:
            db.connection().exec_driver_sql("BEGIN IMMEDIATE")
        row = db.get(ContactProfile, profile_id)
        if not row:
            if existing_id:
                raise HTTPException(404, "Contact profile no longer exists")
            row = ContactProfile(id=profile_id)
            db.add(row)
        row.name = name.strip()
        row.fields = json.dumps(fields)
        row.updated = datetime.now(timezone.utc)
        db.commit()
    return {"id": profile_id, "ok": True}


@app.delete("/api/profiles/{profile_id}")
def delete_profile(request: Request, profile_id: str):
    require_admin(request)
    require_csrf(request)
    with Session() as db:
        db.connection().exec_driver_sql("BEGIN IMMEDIATE")
        profile = db.get(ContactProfile, profile_id)
        if not profile:
            raise HTTPException(404, "Contact profile no longer exists")
        reference = db.execute(
            select(Record.kind, Record.name)
            .where(func.json_extract(Record.content, "$.profile_id") == profile_id)
            .order_by(Record.name, Record.id)
            .limit(1)
        ).first()
        if reference:
            raise HTTPException(
                409,
                f'Change the contact profile on the {reference.kind} “{reference.name}” and save it before deleting this profile.',
            )
        db.delete(profile)
        db.commit()
    return {"ok": True}


@app.post("/api/records")
async def save_record(request: Request):
    user = require_login(request)
    require_csrf(request)
    data = await json_object(request)
    kind = data.get("kind", "signature")
    if kind not in ("signature", "template"):
        raise HTTPException(400, "Unsupported record type")
    name = data.get("name", "Untitled")
    if not isinstance(name, str) or not name.strip() or len(name) > 120:
        raise HTTPException(400, "Enter a record name of up to 120 characters")
    content = validated_content(data.get("content", {}))
    if kind == "template":
        content = template_content(content)
    existing_id = optional_id(data.get("id"))
    record_id = existing_id or str(uuid.uuid4())
    publish = data.get("publish") is True
    if publish and kind != "signature":
        raise HTTPException(400, "Only signatures can be published")
    with Session() as db:
        if content.get("profile_id"):
            # Serialize profile validation with deletion so a save cannot create a dangling reference.
            db.connection().exec_driver_sql("BEGIN IMMEDIATE")
        fields = profile_values(db, content, require_existing=True)
        row = readable_record(db, record_id, user) if existing_id else None
        if row and row.kind == "template" and not user["is_admin"] and row.owner_id != user["id"]:
            raise HTTPException(403, "Only the template creator or an administrator can edit it")
        if row and row.kind != kind:
            raise HTTPException(400, "Record type cannot be changed")
        if not row:
            row = Record(id=record_id, kind=kind, owner_id=user.get("id"))
            db.add(row)
        row.name = name.strip()
        row.content = json.dumps(content)
        row.updated = datetime.now(timezone.utc)
        if data.get("source_html") is not None:
            row.source_html = checked_source(data["source_html"])
        if publish:
            row.published_html = publish_snapshot(content, fields)
            row.published = True
        db.commit()
    return {"id": record_id, "ok": True}

@app.delete("/api/records/{record_id}")
def delete_record(request: Request, record_id: str):
    require_admin(request)
    require_csrf(request)
    with Session() as db:
        row=db.get(Record,record_id)
        if not row: raise HTTPException(404,"Record not found")
        db.delete(row); db.commit()
    return {"ok":True}

@app.post("/api/import")
async def import_html(request: Request):
    require_login(request)
    require_csrf(request)
    data = await json_object(request)
    raw = checked_source(data.get("html", ""))
    safe = clean_markup(raw)
    warnings = ["Imported source is retained for reference. Rebuild it with editor blocks to export or publish."]
    if safe != raw:
        warnings.append("The preview changed or removed markup during sanitization.")
    return {"safe_html": safe, "source_html": raw, "warnings": warnings}


@app.post("/api/preview")
async def preview_record(request: Request):
    require_login(request)
    require_csrf(request)
    data = await json_object(request)
    content = validated_content(data.get("content", {}))
    with Session() as db:
        fields = profile_values(db, content)
    if data.get("editor") is True:
        result = {"html": render_blocks(content, fields, asset_origin=""), "tiles": editor_tiles(content, fields),
                  "image_origin_configured": bool(public_base())}
        if data.get("check_export") is True:
            try:
                result["copy_html"] = publish_snapshot(content, fields, for_email=True)
            except HTTPException as error:
                result["copy_issue"] = error.detail
        return result
    output = render_blocks(content, fields)
    return {"html": output, "has_local_images": bool(LOCAL_IMAGE_SRC.search(output)),
            "image_origin_configured": bool(public_base())}


def editor_tiles(content, fields):
    tiles = {}
    font = font_stack(content.get("font"))
    align = alignment(content.get("align"))
    for row, block in enumerate(content.get("blocks", [])):
        if block.get("type") != "section":
            tiles[str(row)] = editor_tile(block, fields, align, font)
            continue
        section_align = alignment(block.get("align"), align)
        for col, column in enumerate(block["columns"]):
            for index, child in enumerate(column):
                tiles[f"{row}.{col}.{index}"] = editor_tile(child, fields, section_align, font)
    return tiles


def editor_tile(block, fields, align, font):
    rows = render_rows([{**block, "hidden": False}], fields, align, font=font, asset_origin="")
    return email_table(rows) if rows else ""


def vcard_text(value):
    return value.replace("\\", "\\\\").replace(";", "\\;").replace(",", "\\,")


def fold_vcard_line(line):
    chunks = []
    chunk = bytearray()
    for character in line:
        encoded = character.encode("utf-8")
        if len(chunk) + len(encoded) > 75:
            chunks.append(bytes(chunk))
            chunk = bytearray(b" ")
        chunk.extend(encoded)
    chunks.append(bytes(chunk))
    return b"\r\n".join(chunks)


def qr_ink(color):
    if not isinstance(color, str) or not re.fullmatch(r"#[0-9a-fA-F]{6}", color):
        return "#000000"
    channels = [int(color[index:index + 2], 16) / 255 for index in (1, 3, 5)]
    linear = [value / 12.92 if value <= .04045 else ((value + .055) / 1.055) ** 2.4 for value in channels]
    luminance = sum(value * weight for value, weight in zip(linear, (.2126, .7152, .0722)))
    return color if 1.05 / (luminance + .05) >= 4.5 else "#000000"


@app.post("/api/export/contact-qr")
async def export_contact_qr(request: Request):
    require_login(request)
    require_csrf(request)
    data = await json_object(request)
    fields = {}
    for key, limit in {"name": 120, "company": 120, "title": 120, "email": 254, "phone": 50, "website": 254}.items():
        value = data.get(key, "")
        if not isinstance(value, str) or len(value) > limit or (value and not value.isprintable()):
            raise HTTPException(400, f"Enter a single line for {key} (up to {limit} characters).")
        fields[key] = value.strip()
    if not fields["name"]:
        raise HTTPException(400, "Enter a full name for the contact.")
    if fields["email"]:
        href, address = block_link({"type": "email", "href": fields["email"]}, {})
        if not href:
            raise HTTPException(400, "Enter a valid email address.")
        fields["email"] = address
    if fields["phone"] and not re.fullmatch(r"\+?[0-9][0-9 ().-]*|\([0-9]+\)[0-9 ().-]+", fields["phone"]):
        raise HTTPException(400, "Enter a phone number using digits and standard phone punctuation.")
    region = data.get("country_region")
    if fields["phone"] and isinstance(region, str) and region in phonenumbers.SUPPORTED_REGIONS:
        href, _ = block_link({"type": "phone", "href": fields["phone"], "country_region": region}, {})
        if not href:
            raise HTTPException(400, "Enter a complete phone number for the selected country.")
        fields["phone"] = href.removeprefix("tel:")
    if fields["website"]:
        fields["website"] = website_url(fields["website"], {"https"})
        if not fields["website"]:
            raise HTTPException(400, "Enter a valid website URL.")

    name = vcard_text(fields["name"])
    lines = ["BEGIN:VCARD", "VERSION:3.0", f"FN:{name}", f"N:;{name};;;"]
    for key, prop in (("company", "ORG"), ("title", "TITLE"), ("email", "EMAIL;TYPE=INTERNET"),
                      ("phone", "TEL;TYPE=VOICE"), ("website", "URL")):
        if fields[key]:
            value = fields[key] if key == "website" else vcard_text(fields[key])
            lines.append(f"{prop}:{value}")
    lines.append("END:VCARD")
    card = b"\r\n".join(map(fold_vcard_line, lines)) + b"\r\n"
    if len(card) > 900:
        raise HTTPException(400, "Shorten the contact details to make the QR code easier to scan.")
    qr = qrcode.QRCode(box_size=8, border=4)
    qr.add_data(card)
    png = io.BytesIO()
    ink = qr_ink(data.get("color"))
    qr.make_image(fill_color=ink, back_color="white").save(png, format="PNG")
    return Response(
        content=json.dumps({"vcard": card.decode(), "png": base64.b64encode(png.getvalue()).decode("ascii"), "color": ink}),
        media_type="application/json",
        headers={"Cache-Control": "no-store"},
    )


@app.post("/api/export/bundle")
async def export_bundle(request: Request):
    user = require_login(request)
    require_csrf(request)
    data = await json_object(request)
    published_id = optional_id(data.get("published_id"))
    content = validated_content(data.get("content", {})) if not published_id else None
    with Session() as db:
        if published_id:
            snapshot = get_published_html(readable_record(db, published_id, user))
            origin = html.escape(public_base(), quote=True)
            asset_refs = LOCAL_IMAGE_SRC
            if origin:
                asset_refs = re.compile(
                    LOCAL_IMAGE_SRC.pattern.replace(")(/media/", f")(?:{re.escape(origin)})?(/media/", 1)
                )
            output = asset_refs.sub(r'\1.\2"', snapshot)
        else:
            output = render_blocks(content, profile_values(db, content), asset_origin=".")
    names = set(re.findall(r'src="\./(media/(?:[0-9a-f]{32}\.(?:png|jpg|gif|webp)|social/[a-z]+\.png))"', output))
    files = {}
    size = 0
    for name in sorted(names):
        path = SOCIAL_DIR / name.rsplit("/", 1)[1] if name.startswith("media/social/") else MEDIA / name[6:]
        if not path.is_file() or path.is_symlink():
            raise HTTPException(409, "An image is missing. Upload it again before exporting.")
        size += path.stat().st_size
        if size > 64 * 1024 * 1024:
            raise HTTPException(413, "The image bundle exceeds 64 MB.")
        files[name] = path
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, "w") as bundle:
        bundle.writestr("signature.html", '<!doctype html><html lang="en"><head><meta charset="utf-8">'
                        '<meta name="viewport" content="width=device-width, initial-scale=1">'
                        '<title>Email signature</title></head><body>' + output + '</body></html>')
        bundle.writestr("README.txt", "Extract the ZIP and open signature.html in a browser. "
                        "Keep the media folder beside signature.html.\n"
                        "For email delivery, upload the media folder to a recipient-accessible HTTPS host. "
                        "Replace ./media/ in signature.html with that host's absolute HTTPS media URL "
                        "before installing the signature. External HTTPS URLs are already absolute.\n"
                        "Social brand icons: Font Awesome 6.7.2, CC BY 4.0, rasterized and recolored.\n"
                        "https://fontawesome.com/license/free\n")
        for name, path in files.items():
            bundle.write(path, name)
    return Response(archive.getvalue(), media_type="application/zip",
                    headers={"Content-Disposition": 'attachment; filename="signature-and-images.zip"'})

@app.post("/api/assets")
async def upload_asset(request: Request, file: UploadFile=File(...)):
    require_login(request); require_csrf(request)
    data=await file.read(8*1024*1024+1)
    if len(data)>8*1024*1024: raise HTTPException(413,"Maximum image size is 8 MB")
    formats = {"PNG": "png", "JPEG": "jpg", "GIF": "gif", "WEBP": "webp"}
    try:
        with Image.open(io.BytesIO(data), formats=tuple(formats)) as image:
            width, height = image.size
            if width > 6000 or height > 6000:
                raise HTTPException(400, "Image dimensions cannot exceed 6000×6000")
            ext = formats[image.format]
            image.verify()
    except (OSError, SyntaxError, Image.DecompressionBombError):
        raise HTTPException(400, "Upload must be a valid PNG, JPEG, GIF, or WebP")
    filename = f"{uuid.uuid4().hex}.{ext}"
    (MEDIA / filename).write_bytes(data)
    base=public_base()
    return {"url":f"{base}/media/{filename}" if base else f"/media/{filename}","name":file.filename,"width":width,"height":height}

def get_published_html(record):
    if not record or not record.published:
        raise HTTPException(404, "This signature has no published snapshot")
    if not record.published_html:
        raise HTTPException(409, "Legacy publication has no saved HTML. Review the draft and publish again.")
    return record.published_html


@app.get("/api/render/{record_id}")
def render_record(request: Request, record_id: str, published: bool=False):
    user = require_login(request)
    with Session() as db:
        r = readable_record(db, record_id, user)
        if published:
            snapshot = get_published_html(r)
            return {"html": snapshot, "published": True, "has_local_images": bool(LOCAL_IMAGE_SRC.search(snapshot))}
        content = json.loads(r.content)
        if r.kind == "template":
            content = template_content(content)
        return {"html": render_blocks(content, profile_values(db, content)), "published": r.published,
                "published_html": r.published_html}


def directory_identity_exists(user_id):
    with Session() as db:
        return db.scalar(select(DirectoryIdentity).where(DirectoryIdentity.user_id == user_id)) is not None


community = Community(__import__(__name__, fromlist=["app"]))
community.sync()
if community.setup_needed():
    persistent_secret(DATA, "setup-token")
    print("Installation is unclaimed. Open /setup and read the setup-token file in the data volume.", flush=True)
community.install_routes()


@app.middleware("http")
async def installation_settings(request: Request, call_next):
    community.sync()
    response = await call_next(request)
    if request.url.path in ("/", "/login", "/setup") or request.url.path.startswith("/api/") or request.url.path.startswith("/auth/"):
        response.headers["Cache-Control"] = "no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"
    return response
