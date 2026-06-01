import asyncio
import hashlib
import hmac
import json
import logging
import os
import re
import secrets
import xml.etree.ElementTree as ET
from contextlib import asynccontextmanager
from datetime import date
from pathlib import Path
from time import perf_counter
from typing import Any, Callable

import aiohttp
import aiosqlite
from fastapi import (
    Depends,
    FastAPI,
    File,
    Form,
    HTTPException,
    Request,
    Response,
    UploadFile,
)
from fastapi.exceptions import RequestValidationError
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from itsdangerous import BadSignature, Signer
from pydantic import BaseModel


CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
COMMON_PORT_SERVICES = {
    "21": "ftp",
    "22": "ssh",
    "25": "smtp",
    "53": "dns",
    "80": "http",
    "110": "pop3",
    "143": "imap",
    "443": "https",
    "465": "smtps",
    "587": "submission",
    "993": "imaps",
    "995": "pop3s",
    "3306": "mysql",
    "5432": "postgresql",
    "6379": "redis",
    "8080": "http-alt",
    "8443": "https-alt",
}


BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "database.db"
UPLOAD_DIR = BASE_DIR / "uploads"
STATIC_DIR = BASE_DIR / "static"
TEMPLATE_DIR = BASE_DIR / "templates"
ENV_PATH = BASE_DIR / ".env"


def load_env_file(path: Path) -> dict[str, Any]:
    result: dict[str, Any] = {"path": str(path), "found": path.exists(), "loaded": [], "skipped": []}
    if not path.exists():
        return result

    with path.open("r", encoding="utf-8", errors="ignore") as handle:
        for line_number, raw_line in enumerate(handle, start=1):
            line = raw_line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            key = key.strip()
            value = value.strip().strip('"').strip("'")
            if not key:
                result["skipped"].append(f"line:{line_number}")
                continue
            if key in os.environ:
                result["skipped"].append(key)
                continue
            os.environ[key] = value
            result["loaded"].append(key)
    return result


ENV_FILE_STATUS = load_env_file(ENV_PATH)

SECRET_KEY = os.environ.get("SECDASH_SECRET_KEY", "sec-dash-dev-secret-change-me")
SESSION_COOKIE = "session_token"
ALLOWED_UPLOAD_SUFFIXES = {".xml", ".nmap", ".gnmap", ".txt", ".json", ".csv"}
MAX_UPLOAD_BYTES = 10 * 1024 * 1024
CVE_REQUEST_DELAY_SECONDS = float(os.environ.get("CVE_REQUEST_DELAY_SECONDS", "5"))
GROQ_API_URL = os.environ.get("GROQ_API_URL", "https://api.groq.com/openai/v1/chat/completions")
GROQ_MODEL = os.environ.get("GROQ_MODEL", "llama-3.3-70b-versatile")
GROQ_TIMEOUT_SECONDS = int(os.environ.get("GROQ_TIMEOUT_SECONDS", "30"))

UBUNTU_VERSIONS = [
    "24.04 LTS",
    "23.10",
    "23.04",
    "22.04 LTS",
    "21.10",
    "21.04",
    "20.10",
    "20.04 LTS",
    "19.10",
    "18.04 LTS",
]
RHEL_VERSIONS = ["9.4", "9.3", "9.2", "9.1", "9.0", "8.10", "8.9", "8.8", "8.7", "8.6"]
OS_VERSIONS = {"ubuntu": UBUNTU_VERSIONS, "rhel": RHEL_VERSIONS}
UBUNTU_CODENAMES = {
    "24.04 LTS": "noble",
    "23.10": "mantic",
    "23.04": "lunar",
    "22.04 LTS": "jammy",
    "21.10": "impish",
    "21.04": "hirsute",
    "20.10": "groovy",
    "20.04 LTS": "focal",
    "19.10": "eoan",
    "18.04 LTS": "bionic",
}

app = FastAPI(title="Security Research Dashboard")
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
templates = Jinja2Templates(directory=TEMPLATE_DIR)
signer = Signer(SECRET_KEY)
logger = logging.getLogger("secdash")

# Last parsed result per workspace. This is intentionally temporary; saved reports persist in SQLite.
PARSE_CACHE: dict[int, dict[str, Any]] = {}


def groq_key_status() -> dict[str, Any]:
    key = os.environ.get("GROQ_API_KEY", "").strip()
    if not key:
        return {"enabled": False, "state": "missing", "masked": "-"}
    if key == "your_groq_api_key_here" or key.lower().startswith(("your_", "replace_", "change_me")):
        return {"enabled": False, "state": "placeholder", "masked": "-"}
    masked = f"{key[:6]}...{key[-4:]}" if len(key) >= 12 else "***"
    return {"enabled": True, "state": "configured", "masked": masked}


class LoginPayload(BaseModel):
    username: str
    password: str


class UserCreatePayload(BaseModel):
    username: str
    password: str
    role: str


class ResetPasswordPayload(BaseModel):
    new_password: str


class WorkspaceCreatePayload(BaseModel):
    ip: str
    os: str
    os_version: str
    scan_date: date


class CveApiError(RuntimeError):
    def __init__(
        self,
        message: str,
        *,
        status_code: int | None = None,
        api_name: str | None = None,
        url: str | None = None,
        body_preview: str | None = None,
    ):
        super().__init__(message)
        self.status_code = status_code
        self.api_name = api_name
        self.url = url
        self.body_preview = body_preview


def api_error(status_code: int, error: str, detail: str) -> HTTPException:
    return HTTPException(status_code=status_code, detail={"error": error, "detail": detail})


@app.exception_handler(HTTPException)
async def http_exception_handler(_: Request, exc: HTTPException) -> JSONResponse:
    if isinstance(exc.detail, dict) and "error" in exc.detail:
        return JSONResponse(status_code=exc.status_code, content=exc.detail)
    return JSONResponse(
        status_code=exc.status_code,
        content={"error": "Request failed", "detail": str(exc.detail)},
    )


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(_: Request, exc: RequestValidationError) -> JSONResponse:
    return JSONResponse(
        status_code=422,
        content={"error": "Validation failed", "detail": exc.errors()},
    )


@asynccontextmanager
async def db_connect():
    db = await aiosqlite.connect(DB_PATH)
    db.row_factory = aiosqlite.Row
    await db.execute("PRAGMA foreign_keys = ON")
    try:
        yield db
    finally:
        await db.close()


def hash_password(password: str, salt: str | None = None) -> str:
    salt = salt or secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 180_000)
    return f"pbkdf2_sha256${salt}${digest.hex()}"


def verify_password(password: str, stored_hash: str) -> bool:
    try:
        algorithm, salt, expected = stored_hash.split("$", 2)
    except ValueError:
        return False
    if algorithm != "pbkdf2_sha256":
        return False
    actual = hash_password(password, salt).split("$", 2)[2]
    return hmac.compare_digest(actual, expected)


def sign_session_token(raw_token: str) -> str:
    return signer.sign(raw_token.encode("utf-8")).decode("utf-8")


def unsign_session_token(signed_token: str) -> str | None:
    try:
        return signer.unsign(signed_token).decode("utf-8")
    except BadSignature:
        return None


async def get_current_user(request: Request) -> dict[str, Any]:
    signed_token = request.cookies.get(SESSION_COOKIE)
    if not signed_token:
        raise api_error(401, "Unauthorized", "Session expired or not found")

    token = unsign_session_token(signed_token)
    if not token:
        raise api_error(401, "Unauthorized", "Session expired or not found")

    async with db_connect() as db:
        cursor = await db.execute(
            """
            SELECT users.id, users.username, users.role, users.created_at
            FROM sessions
            JOIN users ON users.id = sessions.user_id
            WHERE sessions.token = ?
            """,
            (token,),
        )
        row = await cursor.fetchone()
    if not row:
        raise api_error(401, "Unauthorized", "Session expired or not found")
    return dict(row)


def require_role(*roles: str) -> Callable:
    async def dependency(user: dict[str, Any] = Depends(get_current_user)) -> dict[str, Any]:
        if user["role"] not in roles:
            raise api_error(403, "Forbidden", "Your role cannot access this resource")
        return user

    return dependency


def validate_role(role: str, allow_admin: bool = True) -> str:
    allowed = {"admin", "researcher", "viewer"} if allow_admin else {"researcher", "viewer"}
    if role not in allowed:
        raise api_error(422, "Validation failed", f"Role must be one of: {', '.join(sorted(allowed))}")
    return role


def validate_workspace_input(payload: WorkspaceCreatePayload) -> None:
    if not re.match(r"^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$", payload.ip):
        raise api_error(422, "Validation failed", "IP address must be a valid IPv4 address")
    if payload.os not in OS_VERSIONS:
        raise api_error(422, "Validation failed", "OS must be ubuntu or rhel")
    if payload.os_version not in OS_VERSIONS[payload.os]:
        raise api_error(422, "Validation failed", "Unsupported OS version")


def workspace_name(ip: str, os_name: str, os_version: str, scan_date: date | str) -> str:
    label = "Ubuntu" if os_name == "ubuntu" else "RHEL"
    return f"{ip} - {label} {os_version} - {scan_date}"


def normalize_severity(value: Any) -> str:
    if not value:
        return "UNKNOWN"
    severity = str(value).strip().upper()
    if severity in {"CRITICAL"}:
        return "CRITICAL"
    if severity in {"HIGH", "IMPORTANT"}:
        return "HIGH"
    if severity in {"MEDIUM", "MODERATE"}:
        return "MEDIUM"
    if severity == "LOW":
        return "LOW"
    return "UNKNOWN"


def severity_rank(value: Any) -> int:
    return {"UNKNOWN": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}.get(normalize_severity(value), 0)


def xml_name(element: ET.Element) -> str:
    return element.tag.rsplit("}", 1)[-1].lower()


def child_by_name(element: ET.Element, name: str) -> ET.Element | None:
    wanted = name.lower()
    for child in list(element):
        if xml_name(child) == wanted:
            return child
    return None


def child_text(element: ET.Element, name: str) -> str | None:
    child = child_by_name(element, name)
    if child is None:
        return None
    text = "".join(child.itertext()).strip()
    return text or None


def clean_port(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    match = re.search(r"\d{1,5}", text)
    if not match:
        return None
    port = int(match.group(0))
    if port < 1 or port > 65535:
        return None
    return str(port)


def parse_port_proto(value: Any) -> tuple[str | None, str | None, str]:
    text = str(value or "").strip()
    if not text:
        return None, None, ""

    slash_match = re.search(r"\b(?P<port>\d{1,5})\s*/\s*(?P<proto>tcp|udp)\b", text, re.IGNORECASE)
    if slash_match:
        return clean_port(slash_match.group("port")), slash_match.group("proto").lower(), text[slash_match.end() :].strip(" ,")

    csv_match = re.match(r"\s*(?P<port>\d{1,5})\s*,\s*(?P<proto>tcp|udp)\s*,?\s*(?P<rest>.*)", text, re.IGNORECASE | re.DOTALL)
    if csv_match:
        return clean_port(csv_match.group("port")), csv_match.group("proto").lower(), csv_match.group("rest").strip()

    if re.fullmatch(r"\d{1,5}", text):
        return clean_port(text), None, ""
    return None, None, text


def cpe_parts(cpe: Any) -> dict[str, str]:
    text = str(cpe or "").strip()
    if not text.startswith("cpe:"):
        return {}
    if text.startswith("cpe:/"):
        parts = text[5:].split(":")
        return {
            "part": parts[0] if len(parts) > 0 else "",
            "vendor": parts[1] if len(parts) > 1 else "",
            "product": parts[2] if len(parts) > 2 else "",
            "version": parts[3] if len(parts) > 3 else "",
        }
    if text.startswith("cpe:2.3:"):
        parts = text.split(":")
        return {
            "part": parts[2] if len(parts) > 2 else "",
            "vendor": parts[3] if len(parts) > 3 else "",
            "product": parts[4] if len(parts) > 4 else "",
            "version": parts[5] if len(parts) > 5 else "",
        }
    return {}


def cpe_product_label(cpe: Any) -> tuple[str, str]:
    parts = cpe_parts(cpe)
    vendor = parts.get("vendor", "").lower()
    product = parts.get("product", "").lower()
    version = parts.get("version", "")
    known = {
        ("apache", "http_server"): "Apache httpd",
        ("openbsd", "openssh"): "OpenSSH",
        ("ietf", "secure_shell_protocol"): "SSH protocol",
        ("php", "php"): "PHP",
        ("jquery", "jquery"): "jQuery",
        ("osticket", "osticket"): "osTicket",
    }
    label = known.get((vendor, product))
    if not label and product:
        label = product.replace("_", " ").replace("-", " ").strip().title()
    return label or "", "" if version in {"", "-", "*"} else version


def service_from_cpe(cpe: Any, location: Any = None) -> tuple[str | None, str | None]:
    port, proto, _ = parse_port_proto(location)
    text = str(cpe or "").lower()
    if not port:
        if any(token in text for token in ("openbsd:openssh", "secure_shell_protocol", "openssh")):
            port = "22"
        elif any(token in text for token in ("apache:http_server", "php:php", "jquery:jquery", "osticket:osticket", "http_server")):
            port = "80"
    return port, proto


def service_extra(value: Any, limit: int = 220) -> str:
    text = clean_text(value) or ""
    if len(text) <= limit:
        return text
    return f"{text[: limit - 3].rstrip()}..."


def service_label(port: Any = None, service: Any = None) -> str:
    cleaned = str(service or "").strip()
    if cleaned:
        return cleaned
    port_text = clean_port(port)
    return COMMON_PORT_SERVICES.get(port_text or "", "unknown")


def add_service(
    services: list[dict[str, Any]],
    *,
    port: Any,
    proto: Any = "tcp",
    state: Any = "open",
    service: Any = None,
    product: Any = None,
    version: Any = None,
    extra: Any = None,
    ip: Any = None,
    source: str | None = None,
    cpes: list[str] | None = None,
    cves: list[str] | None = None,
) -> None:
    port_text = clean_port(port)
    if not port_text:
        return
    item = {
        "port": port_text,
        "proto": str(proto or "tcp").strip().lower(),
        "state": str(state or "open").strip().lower(),
        "service": service_label(port_text, service),
        "product": str(product or "").strip(),
        "version": str(version or "").strip(),
        "extra": str(extra or "").strip(),
        "ip": str(ip or "").strip(),
        "source": source or "",
        "cpes": cpes or [],
        "cves": sorted(set(cves or [])),
    }
    key = (
        item["port"],
        item["proto"],
        item["state"],
        item["service"],
        item["product"],
        item["version"],
        item["extra"],
    )
    existing_keys = {
        (
            existing.get("port"),
            existing.get("proto"),
            existing.get("state"),
            existing.get("service"),
            existing.get("product"),
            existing.get("version"),
            existing.get("extra"),
        )
        for existing in services
    }
    if key not in existing_keys:
        services.append(item)
    else:
        for existing in services:
            existing_key = (
                existing.get("port"),
                existing.get("proto"),
                existing.get("state"),
                existing.get("service"),
                existing.get("product"),
                existing.get("version"),
                existing.get("extra"),
            )
            if existing_key == key:
                existing["cves"] = sorted(set((existing.get("cves") or []) + item["cves"]))
                existing["cpes"] = sorted(set((existing.get("cpes") or []) + item["cpes"]))
                break


def add_application(
    applications: list[dict[str, Any]],
    *,
    cpe: Any,
    source: str | None = None,
    location: Any = None,
    ip: Any = None,
    occurrences: int = 1,
) -> None:
    cpe_text = str(cpe or "").strip()
    if not cpe_text.startswith("cpe:"):
        return
    product, version = cpe_product_label(cpe_text)
    location_text = str(location or "").strip()
    item = {
        "cpe": cpe_text,
        "product": product,
        "version": version,
        "ip": str(ip or "").strip(),
        "source": source or "",
        "locations": [location_text] if location_text else [],
        "occurrences": max(1, int(occurrences or 1)),
    }
    for existing in applications:
        if existing.get("cpe") != cpe_text:
            continue
        existing["locations"] = sorted(set((existing.get("locations") or []) + item["locations"]))
        existing["occurrences"] = max(existing.get("occurrences") or 1, item["occurrences"])
        if not existing.get("ip") and item["ip"]:
            existing["ip"] = item["ip"]
        return
    applications.append(item)


def add_scan_result(
    results: list[dict[str, Any]],
    *,
    result_id: Any = None,
    scanner: str,
    name: Any,
    severity: Any = None,
    threat: Any = None,
    qod: Any = None,
    host: Any = None,
    port: Any = None,
    proto: Any = None,
    location: Any = None,
    family: Any = None,
    description: Any = None,
    solution: Any = None,
    cves: list[str] | None = None,
    cpes: list[str] | None = None,
    created_at: Any = None,
    source: str | None = None,
) -> None:
    name_text = clean_text(name)
    if not name_text:
        return
    port_text, parsed_proto, _ = parse_port_proto(location or port)
    item = {
        "id": str(result_id or "").strip(),
        "scanner": scanner,
        "name": name_text,
        "severity": to_float(severity),
        "threat": str(threat or "").strip(),
        "qod": to_float(qod),
        "host": str(host or "").strip(),
        "port": port_text or clean_port(port),
        "proto": str(proto or parsed_proto or "tcp").strip().lower(),
        "location": str(location or "").strip(),
        "family": str(family or "").strip(),
        "description": clean_text(description) or "",
        "solution": clean_text(solution) or "",
        "cves": sorted(set(cves or [])),
        "cpes": sorted(set(cpes or [])),
        "created_at": str(created_at or "").strip(),
        "source": source or "",
    }
    key = (item["scanner"], item["id"], item["name"], item["host"], item["location"], item["port"])
    for existing in results:
        existing_key = (
            existing.get("scanner"),
            existing.get("id"),
            existing.get("name"),
            existing.get("host"),
            existing.get("location"),
            existing.get("port"),
        )
        if existing_key != key:
            continue
        existing["cves"] = sorted(set((existing.get("cves") or []) + item["cves"]))
        existing["cpes"] = sorted(set((existing.get("cpes") or []) + item["cpes"]))
        return
    results.append(item)


def parse_target_port(target: Any) -> tuple[str | None, str | None]:
    text = str(target or "").strip()
    match = re.search(r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3})?(?::(?P<port>\d{1,5}))$", text)
    if not match:
        return None, clean_port(text)
    return match.group("ip"), clean_port(match.group("port"))


def extract_cves_from_text(text: str) -> list[str]:
    return sorted({cve.upper() for cve in CVE_PATTERN.findall(text or "")})


def parse_jsonish_values(text: str) -> list[Any]:
    candidates = [text]
    repaired = re.sub(r",\s*,+", ",", text)
    repaired = re.sub(r"\[\s*,", "[", repaired)
    repaired = re.sub(r",\s*\]", "]", repaired)
    if repaired != text:
        candidates.append(repaired)

    for candidate in candidates:
        try:
            data = json.loads(candidate)
            return data if isinstance(data, list) else [data]
        except json.JSONDecodeError:
            continue

    decoder = json.JSONDecoder()
    values: list[Any] = []
    index = 0
    while index < len(text):
        while index < len(text) and text[index] in " \r\n\t,[]":
            index += 1
        if index >= len(text):
            break
        try:
            value, next_index = decoder.raw_decode(text, index)
        except json.JSONDecodeError:
            index += 1
            continue
        values.append(value)
        index = next_index
    return values


def service_hints_from_cpes(cpes: list[str], cves: list[str], path: Path) -> list[dict[str, Any]]:
    hints: list[dict[str, Any]] = []
    for cpe in cpes:
        port, proto = service_from_cpe(cpe)
        if not port:
            continue
        product, version = cpe_product_label(cpe)
        add_service(
            hints,
            port=port,
            proto=proto or "tcp",
            state="open",
            service=service_label(port),
            product=product,
            version=version,
            source=path.name,
            cpes=[cpe],
            cves=cves,
        )
    return hints


def collect_cpes(value: Any) -> list[str]:
    result: list[str] = []
    if isinstance(value, dict):
        criteria = value.get("criteria")
        if isinstance(criteria, str) and criteria.startswith("cpe:"):
            result.append(criteria)
        for key, item in value.items():
            if isinstance(key, str) and key.startswith("cpe:"):
                result.append(key)
            if isinstance(item, str) and item.startswith("cpe:"):
                result.append(item)
        for item in value.values():
            result.extend(collect_cpes(item))
    elif isinstance(value, list):
        for item in value:
            result.extend(collect_cpes(item))
    elif isinstance(value, str) and value.startswith("cpe:"):
        result.append(value)
    return sorted(set(result))


def collect_xml_cpes(element: ET.Element) -> list[str]:
    raw = ET.tostring(element, encoding="unicode", method="xml")
    cpes = re.findall(r"cpe:(?:/|2\.3:)[^\s<>'\"]+", raw, re.IGNORECASE)
    return sorted({cpe.rstrip(".,;|") for cpe in cpes})


def openvas_detail_source(detail: ET.Element) -> str:
    source = child_by_name(detail, "source")
    if source is None:
        return ""
    return child_text(source, "description") or child_text(source, "name") or ""


def openvas_detection_details(result: ET.Element) -> dict[str, str]:
    details: dict[str, str] = {}
    for detail in result.iter():
        if xml_name(detail) != "detail":
            continue
        name = child_text(detail, "name")
        value = child_text(detail, "value")
        if name and value:
            details[name.lower()] = value
    return details


def parse_json_scan_summary(path: Path, text: str) -> dict[str, Any]:
    cves = set(extract_cves_from_text(text))
    services: list[dict[str, Any]] = []
    results: list[dict[str, Any]] = []
    applications: list[dict[str, Any]] = []
    items = parse_jsonish_values(text)
    if not items:
        return {"cves": sorted(cves), "services": services, "results": results, "applications": applications}

    for item in items:
        if not isinstance(item, dict):
            continue
        item_cves = extract_cves_from_text(json.dumps(item, ensure_ascii=False))
        item_cpes = collect_cpes(item)
        has_detected_service_context = any(key in item for key in ("ports", "target", "banner", "service", "services"))
        if has_detected_service_context:
            for hinted in service_hints_from_cpes(item_cpes, item_cves, path):
                add_service(services, **hinted)
        for key in ("cve", "cve_id", "id"):
            cves.update(extract_cves_from_text(item.get(key, "")))
        ip = item.get("ip") or item.get("host") or item.get("target")
        for port_item in as_list(item.get("ports")):
            if not isinstance(port_item, dict):
                continue
            port_cves = extract_cves_from_text(json.dumps(port_item, ensure_ascii=False))
            add_service(
                services,
                port=port_item.get("port") or port_item.get("portid"),
                proto=port_item.get("proto") or port_item.get("protocol"),
                state=port_item.get("status") or port_item.get("state"),
                service=port_item.get("service") or port_item.get("name"),
                product=port_item.get("product"),
                version=port_item.get("version"),
                extra=port_item.get("reason"),
                ip=ip,
                source=path.name,
                cves=port_cves,
            )
        if "banner" in item or "target" in item:
            target_ip, target_port = parse_target_port(item.get("target"))
            banner = as_dict(item.get("banner"))
            software = banner.get("software") or banner.get("raw") or ""
            add_service(
                services,
                port=target_port,
                proto="tcp",
                state="open",
                service="ssh" if target_port == "22" else None,
                product=software,
                ip=target_ip or ip,
                source=path.name,
                cves=item_cves,
            )
            for index, note in enumerate(as_list(item.get("additional_notes")), start=1):
                note_text = clean_text(note)
                if not note_text:
                    continue
                add_scan_result(
                    results,
                    result_id=f"ssh-audit-{index}",
                    scanner="ssh-audit",
                    name="SSH audit finding",
                    threat="Review",
                    host=target_ip or ip,
                    port=target_port,
                    proto="tcp",
                    location=f"{target_port}/tcp" if target_port else "",
                    family="SSH",
                    description=note_text,
                    cves=extract_cves_from_text(note_text),
                    source=path.name,
                )
        for cve in as_list(item.get("cves")):
            if isinstance(cve, str):
                cves.update(extract_cves_from_text(cve))
            elif isinstance(cve, dict):
                cves.update(extract_cves_from_text(json.dumps(cve, ensure_ascii=False)))

    return {"cves": sorted(cves), "services": services, "results": results, "applications": applications}


def parse_xml_scan_summary(path: Path, text: str) -> dict[str, Any]:
    cves = set(extract_cves_from_text(text))
    services: list[dict[str, Any]] = []
    results: list[dict[str, Any]] = []
    applications: list[dict[str, Any]] = []
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        return {"cves": sorted(cves), "services": services, "results": results, "applications": applications}

    first_address = next(
        (element.attrib.get("addr") for element in root.iter() if xml_name(element) == "address" and element.attrib.get("addr")),
        "",
    )

    for port in root.iter():
        if xml_name(port) != "port":
            continue
        port_cves = extract_cves_from_text(ET.tostring(port, encoding="unicode", method="xml"))
        port_id = port.attrib.get("portid") or (port.text or "").strip()
        parsed_port, parsed_proto, _ = parse_port_proto(port_id)
        proto = port.attrib.get("protocol") or parsed_proto or "tcp"
        state_node = child_by_name(port, "state")
        state = state_node.attrib.get("state") if state_node is not None else "open"
        service_node = child_by_name(port, "service")
        service = service_node.attrib.get("name") if service_node is not None else None
        product = service_node.attrib.get("product") if service_node is not None else None
        version = service_node.attrib.get("version") if service_node is not None else None
        extra = service_node.attrib.get("extrainfo") if service_node is not None else None
        cpes = collect_xml_cpes(service_node) if service_node is not None else []
        add_service(
            services,
            port=parsed_port or port_id,
            proto=proto,
            state=state,
            service=service,
            product=product,
            version=version,
            extra=extra,
            source=path.name,
            cpes=[cpe for cpe in cpes if cpe],
            cves=port_cves,
        )
        for cpe in cpes:
            add_application(
                applications,
                cpe=cpe,
                source=path.name,
                location=f"{parsed_port or clean_port(port_id)}/{proto}",
                ip=first_address,
            )
        for script in port.iter():
            if xml_name(script) != "script":
                continue
            script_output = script.attrib.get("output") or "".join(script.itertext()).strip()
            add_scan_result(
                results,
                result_id=script.attrib.get("id"),
                scanner="nmap",
                name=script.attrib.get("id") or "Nmap script finding",
                host=first_address,
                port=parsed_port or port_id,
                proto=proto,
                location=f"{parsed_port or clean_port(port_id)}/{proto}",
                family="Nmap NSE",
                description=script_output,
                cves=extract_cves_from_text(script_output),
                cpes=collect_xml_cpes(script),
                source=path.name,
            )

    all_details = [detail for detail in root.iter() if xml_name(detail) == "detail"]
    for detail in all_details:
        if (child_text(detail, "name") or "").lower() != "app":
            continue
        cpe = child_text(detail, "value") or ""
        occurrences = sum(1 for candidate in all_details if child_text(candidate, "name") == cpe)
        locations = [child_text(candidate, "value") for candidate in all_details if child_text(candidate, "name") == cpe]
        add_application(
            applications,
            cpe=cpe,
            source=path.name,
            location=next((location for location in locations if location), ""),
            occurrences=occurrences or 1,
        )

    for detail in root.iter():
        if xml_name(detail) != "detail":
            continue
        name = child_text(detail, "name") or ""
        value = child_text(detail, "value") or ""
        source = openvas_detail_source(detail)
        name_lower = name.lower()
        if name_lower == "services":
            port, proto, rest = parse_port_proto(value)
            parts = [part.strip() for part in rest.split(",", 1)]
            detected_service = parts[0] if parts and parts[0] else None
            extra = parts[1] if len(parts) > 1 else source
            add_service(
                services,
                port=port,
                proto=proto or "tcp",
                state="open",
                service=detected_service,
                extra=service_extra(extra or source),
                source=path.name,
            )
            continue

        cpe = value if value.startswith("cpe:") else name if name.startswith("cpe:") else ""
        if not cpe:
            continue
        location = value if name.startswith("cpe:") else None
        port, proto = service_from_cpe(cpe, location)
        if not port:
            continue
        product, version = cpe_product_label(cpe)
        add_service(
            services,
            port=port,
            proto=proto or "tcp",
            state="open",
            service=service_label(port),
            product=product,
            version=version,
            extra=service_extra(source),
            source=path.name,
            cpes=[cpe],
        )

    for detail in root.iter():
        if xml_name(detail) == "scandetails":
            target_port = detail.attrib.get("targetport")
            site = detail.attrib.get("sitename") or detail.attrib.get("siteip") or ""
            add_service(
                services,
                port=target_port,
                proto="tcp",
                state="open",
                service="https" if str(site).lower().startswith("https://") else "http",
                ip=detail.attrib.get("targetip"),
                source=path.name,
            )

    nikto_details = next((element for element in root.iter() if xml_name(element) == "scandetails"), None)
    if nikto_details is not None:
        nikto_host = nikto_details.attrib.get("targetip")
        nikto_port = nikto_details.attrib.get("targetport")
        for item in root.iter():
            if xml_name(item) != "item":
                continue
            description = child_text(item, "description") or ""
            uri = child_text(item, "uri") or ""
            add_scan_result(
                results,
                result_id=item.attrib.get("id"),
                scanner="nikto",
                name=description or f"Nikto finding {item.attrib.get('id') or ''}".strip(),
                threat="Review",
                host=nikto_host,
                port=nikto_port,
                proto="tcp",
                location=uri,
                family="Web scan",
                description=description,
                cves=extract_cves_from_text(ET.tostring(item, encoding="unicode", method="xml")),
                source=path.name,
            )

    for result in root.iter():
        if xml_name(result) != "result":
            continue
        port_value = child_text(result, "port")
        if port_value:
            result_cves = extract_cves_from_text(ET.tostring(result, encoding="unicode", method="xml"))
            result_cpes = collect_xml_cpes(result)
            detection = openvas_detection_details(result)
            cpe = detection.get("product") if str(detection.get("product", "")).startswith("cpe:") else (result_cpes[0] if result_cpes else "")
            product, version = cpe_product_label(cpe)
            port, proto, _ = parse_port_proto(detection.get("location") or port_value)
            nvt = child_by_name(result, "nvt")
            nvt_name = child_text(nvt, "name") if nvt is not None else child_text(result, "name")
            add_service(
                services,
                port=port or port_value,
                proto=proto or ("udp" if "/udp" in port_value.lower() else "tcp"),
                state="open",
                service=service_label(port or port_value),
                product=product,
                version=version,
                extra=service_extra(nvt_name),
                ip=child_text(result, "host"),
                source=path.name,
                cpes=result_cpes,
                cves=result_cves,
            )
            add_scan_result(
                results,
                result_id=result.attrib.get("id"),
                scanner="openvas",
                name=nvt_name or child_text(result, "name") or "OpenVAS finding",
                severity=child_text(result, "severity"),
                threat=child_text(result, "threat"),
                qod=child_text(child_by_name(result, "qod"), "value") if child_by_name(result, "qod") is not None else None,
                host=child_text(result, "host"),
                port=port or port_value,
                proto=proto or ("udp" if "/udp" in port_value.lower() else "tcp"),
                location=port_value,
                family=child_text(nvt, "family") if nvt is not None else None,
                description=child_text(result, "description"),
                solution=child_text(nvt, "solution") if nvt is not None else None,
                cves=result_cves,
                cpes=result_cpes,
                created_at=child_text(result, "creation_time"),
                source=path.name,
            )

    return {"cves": sorted(cves), "services": services, "results": results, "applications": applications}


def parse_scan_file(filepath: str) -> dict[str, Any]:
    path = Path(filepath)
    text = path.read_text(errors="ignore", encoding="utf-8")
    suffix = path.suffix.lower()
    if suffix == ".json":
        return parse_json_scan_summary(path, text)
    if suffix == ".xml":
        return parse_xml_scan_summary(path, text)
    return {"cves": extract_cves_from_text(text), "services": [], "results": [], "applications": []}


def parse_nmap_file(filepath: str) -> list[str]:
    """
    Parse an nmap scan file and return CVE IDs.

    Kept as the CVE-only compatibility wrapper around the richer scan parser.
    """
    return parse_scan_file(filepath)["cves"]


def cached_classification_map(workspace_id: int) -> dict[str, dict[str, Any]]:
    cached = PARSE_CACHE.get(workspace_id) or {}
    result: dict[str, dict[str, Any]] = {}
    for item in (cached.get("needs_attention") or []) + (cached.get("filtered_out") or []):
        cve_id = item.get("cve_id")
        attention = item.get("attention") or {}
        if not cve_id or not attention:
            continue
        result[cve_id] = {
            "cve_id": cve_id,
            "status": "ok",
            "severity": item.get("severity"),
            "attention_needed": attention.get("attention_needed"),
            "status_category": attention.get("status_category"),
            "classifier": attention.get("provider"),
            "confidence": attention.get("confidence"),
            "reason": attention.get("reason"),
            "status_summary": attention.get("status_summary"),
            "target_status_summary": attention.get("target_status_summary"),
        }
    return result


async def collect_file_cves(workspace_id: int, files: list[dict[str, Any]]) -> dict[str, Any]:
    source_map: dict[str, list[str]] = {}
    service_map: dict[tuple[Any, ...], dict[str, Any]] = {}
    result_map: dict[tuple[Any, ...], dict[str, Any]] = {}
    application_map: dict[str, dict[str, Any]] = {}
    file_results: list[dict[str, Any]] = []

    for item in files:
        absolute = UPLOAD_DIR / item["filepath"]
        if not absolute.exists():
            logger.warning(
                "Uploaded scan file missing during local CVE extraction | workspace_id=%s file_id=%s filename=%s filepath=%s",
                workspace_id,
                item["id"],
                item["filename"],
                item["filepath"],
            )
            file_results.append(
                {
                    "id": item["id"],
                    "filename": item["filename"],
                    "status": "missing",
                    "cve_count": 0,
                    "cves": [],
                    "service_count": 0,
                    "result_count": 0,
                    "application_count": 0,
                }
            )
            continue

        parsed_summary = await asyncio.to_thread(parse_scan_file, str(absolute))
        parsed = parsed_summary["cves"]
        services = parsed_summary["services"]
        results = parsed_summary["results"]
        applications = parsed_summary["applications"]
        logger.info(
            "Uploaded scan file locally extracted | workspace_id=%s file_id=%s filename=%s cve_count=%s service_count=%s result_count=%s application_count=%s",
            workspace_id,
            item["id"],
            item["filename"],
            len(parsed),
            len(services),
            len(results),
            len(applications),
        )
        for cve_id in parsed:
            source_map.setdefault(cve_id, []).append(item["filename"])
        for service in services:
            key = (
                service.get("port"),
                service.get("proto"),
                service.get("state"),
            )
            existing = service_map.setdefault(key, {**service, "files": []})
            if existing.get("service") in {"", "unknown"} and service.get("service"):
                existing["service"] = service["service"]
            for field in ("product", "version", "extra", "ip"):
                if not existing.get(field) and service.get(field):
                    existing[field] = service[field]
            existing["cpes"] = sorted(set((existing.get("cpes") or []) + (service.get("cpes") or [])))
            existing["cves"] = sorted(set((existing.get("cves") or []) + (service.get("cves") or [])))
            existing.setdefault("files", []).append(item["filename"])
        for result in results:
            key = (
                result.get("scanner"),
                result.get("id"),
                result.get("name"),
                result.get("host"),
                result.get("location"),
                result.get("port"),
            )
            existing = result_map.setdefault(key, {**result, "files": []})
            existing["cves"] = sorted(set((existing.get("cves") or []) + (result.get("cves") or [])))
            existing["cpes"] = sorted(set((existing.get("cpes") or []) + (result.get("cpes") or [])))
            existing.setdefault("files", []).append(item["filename"])
        for application in applications:
            cpe = application.get("cpe")
            if not cpe:
                continue
            existing = application_map.setdefault(cpe, {**application, "files": []})
            existing["locations"] = sorted(set((existing.get("locations") or []) + (application.get("locations") or [])))
            existing["occurrences"] = max(existing.get("occurrences") or 1, application.get("occurrences") or 1)
            existing.setdefault("files", []).append(item["filename"])
        file_results.append(
            {
                "id": item["id"],
                "filename": item["filename"],
                "status": "ok",
                "cve_count": len(parsed),
                "cves": parsed,
                "service_count": len(services),
                "result_count": len(results),
                "application_count": len(applications),
            }
        )

    classifications = cached_classification_map(workspace_id)
    items = []
    for cve_id, filenames in sorted(source_map.items()):
        item = {
            "cve_id": cve_id,
            "files": sorted(set(filenames)),
            "file_count": len(set(filenames)),
        }
        if cve_id in classifications:
            item["classification"] = classifications[cve_id]
        items.append(item)
    services = []
    for service in service_map.values():
        filenames = sorted(set(service.get("files") or []))
        services.append({**service, "files": filenames, "file_count": len(filenames)})
    services.sort(key=lambda item: (int(item.get("port") or 0), item.get("proto") or "", item.get("service") or ""))
    results = []
    for result in result_map.values():
        filenames = sorted(set(result.get("files") or []))
        results.append({**result, "files": filenames, "file_count": len(filenames)})
    results.sort(key=lambda item: (-(item.get("severity") or 0), item.get("scanner") or "", item.get("name") or ""))
    applications = []
    for application in application_map.values():
        filenames = sorted(set(application.get("files") or []))
        applications.append({**application, "files": filenames, "file_count": len(filenames)})
    applications.sort(key=lambda item: (item.get("product") or "", item.get("version") or "", item.get("cpe") or ""))
    return {
        "items": items,
        "files": file_results,
        "services": services,
        "results": results,
        "applications": applications,
        "classifications": classifications,
        "total": len(items),
        "service_total": len(services),
        "result_total": len(results),
        "application_total": len(applications),
        "classified_total": len(classifications),
    }


def clean_text(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, list):
        parts = [clean_text(item) for item in value]
        return "\n\n".join(part for part in parts if part)
    if isinstance(value, dict):
        for key in ("value", "note", "description", "summary", "statement"):
            if key in value:
                return clean_text(value.get(key))
        return json.dumps(value, ensure_ascii=False)
    text = str(value).replace("\r\n", "\n").replace("\r", "\n")
    text = re.sub(r"\n{3,}", "\n\n", text)
    text = re.sub(r"[ \t]+", " ", text)
    return text.strip() or None


def as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def as_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def unique_clean(values: list[Any]) -> list[str]:
    seen = set()
    result = []
    for value in values:
        text = clean_text(value)
        if text and text not in seen:
            seen.add(text)
            result.append(text)
    return result


def to_float(value: Any) -> float | None:
    if value in (None, ""):
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def split_references(values: Any) -> list[str]:
    refs = []
    for item in as_list(values):
        if isinstance(item, str):
            refs.extend(part.strip() for part in item.splitlines() if part.strip())
        else:
            text = clean_text(item)
            if text:
                refs.append(text)
    return unique_clean(refs)


def dedupe_links(links: list[dict[str, str]]) -> list[dict[str, str]]:
    seen = set()
    result = []
    for link in links:
        url = link.get("url")
        label = link.get("label")
        if not url or not label or url in seen:
            continue
        seen.add(url)
        result.append({"label": label, "url": url})
    return result


def official_rhel_links(cve_id: str, api_url: str, advisories: list[str]) -> list[dict[str, str]]:
    links = [
        {"label": "Red Hat CVE", "url": f"https://access.redhat.com/security/cve/{cve_id}"},
        {"label": "Red Hat API", "url": api_url},
    ]
    for advisory in advisories[:4]:
        links.append({"label": advisory, "url": f"https://access.redhat.com/errata/{advisory}"})
    return dedupe_links(links)


def official_ubuntu_links(cve_id: str, api_url: str, notice_ids: list[str]) -> list[dict[str, str]]:
    links = [
        {"label": "Ubuntu CVE", "url": f"https://ubuntu.com/security/{cve_id}"},
        {"label": "Ubuntu API", "url": api_url},
    ]
    for notice_id in notice_ids[:4]:
        links.append({"label": notice_id, "url": f"https://ubuntu.com/security/notices/{notice_id}"})
    return dedupe_links(links)


def ubuntu_package_statuses(packages: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, int]]:
    package_summaries = []
    release_statuses = []
    status_counts: dict[str, int] = {}
    for package in packages:
        statuses = as_list(package.get("statuses"))
        package_summaries.append(
            {
                "name": package.get("name"),
                "source": package.get("source"),
                "ubuntu_url": package.get("ubuntu"),
                "debian_url": package.get("debian"),
                "status_count": len(statuses),
            }
        )
        for status in statuses:
            if not isinstance(status, dict):
                continue
            status_value = clean_text(status.get("status")) or "unknown"
            status_counts[status_value] = status_counts.get(status_value, 0) + 1
            release_statuses.append(
                {
                    "package": package.get("name"),
                    "release": status.get("release_codename"),
                    "status": status_value,
                    "pocket": status.get("pocket"),
                    "component": status.get("component"),
                    "description": status.get("description"),
                }
            )
    return package_summaries, release_statuses, status_counts


def ubuntu_notice_summary(notices: list[dict[str, Any]]) -> list[dict[str, Any]]:
    summaries = []
    for notice in notices:
        release_packages = as_dict(notice.get("release_packages"))
        summaries.append(
            {
                "id": notice.get("id"),
                "type": notice.get("type"),
                "title": notice.get("title"),
                "summary": clean_text(notice.get("summary")),
                "description": clean_text(notice.get("description")),
                "instructions": clean_text(notice.get("instructions")),
                "published": notice.get("published"),
                "release_count": len(release_packages),
                "releases": sorted(release_packages.keys()),
                "references": split_references(notice.get("references")),
            }
        )
    return summaries


def rhel_affected_summary(affected: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[str], list[str], list[str]]:
    normalized = []
    advisories = []
    packages = []
    products = []
    for item in affected:
        if not isinstance(item, dict):
            continue
        advisory = item.get("advisory")
        package = item.get("package")
        product = item.get("product_name")
        normalized.append(
            {
                "advisory": advisory,
                "package": package,
                "product_name": product,
                "cpe": item.get("cpe"),
                "release_date": item.get("release_date"),
            }
        )
        advisories.append(advisory)
        packages.append(package)
        products.append(product)
    return normalized, unique_clean(advisories), unique_clean(packages), unique_clean(products)


def normalize_rhel_cve(data: dict[str, Any], cve_id: str, api_name: str, url: str, status_code: int) -> dict[str, Any]:
    cvss3 = as_dict(data.get("cvss3"))
    affected = [item for item in as_list(data.get("affected_release")) if isinstance(item, dict)]
    affected_releases, advisories, affected_packages, products = rhel_affected_summary(affected)
    package_state = [item for item in as_list(data.get("package_state")) if isinstance(item, dict)]
    mitigation = clean_text(data.get("mitigation"))
    statement = clean_text(data.get("statement"))
    details = clean_text(data.get("details"))
    severity_source = data.get("threat_severity")
    severity = normalize_severity(severity_source)
    first_advisory = advisories[0] if advisories else None
    remediation = statement or mitigation or first_advisory or "See Red Hat Security Advisory"

    return {
        "cve_id": data.get("name") or cve_id,
        "source_os": "rhel",
        "source_api": api_name,
        "source_url": url,
        "source_status_code": status_code,
        "api_status": "ok",
        "severity": severity,
        "severity_source": severity_source,
        "cvss_score": to_float(cvss3.get("cvss3_base_score")),
        "cvss_vector": cvss3.get("cvss3_scoring_vector"),
        "cvss_status": cvss3.get("status"),
        "description": details,
        "status": first_advisory,
        "remediation": remediation,
        "ai_summary": None,
        "public_date": data.get("public_date"),
        "published_at": data.get("public_date"),
        "updated_at": None,
        "cwe": data.get("cwe"),
        "references": split_references(data.get("references")),
        "official_links": official_rhel_links(data.get("name") or cve_id, url, advisories),
        "advisories": advisories,
        "affected_releases": affected_releases,
        "affected_packages": affected_packages,
        "affected_products": products,
        "package_states": package_state,
        "package_state_count": len(package_state),
        "affected_release_count": len(affected_releases),
        "bugzilla": data.get("bugzilla") if isinstance(data.get("bugzilla"), dict) else None,
        "mitigation": mitigation,
        "statement": statement,
        "csaw": data.get("csaw"),
        "provider_fields": {
            "threat_severity": data.get("threat_severity"),
            "has_affected_release": bool(affected_releases),
            "has_package_state": bool(package_state),
        },
    }


def normalize_ubuntu_cve(data: dict[str, Any], cve_id: str, api_name: str, url: str, status_code: int) -> dict[str, Any]:
    impact_cvss = as_dict(as_dict(as_dict(data.get("impact")).get("baseMetricV3")).get("cvssV3"))
    cvss3 = data.get("cvss3")
    packages = [item for item in as_list(data.get("packages")) if isinstance(item, dict)]
    package_summaries, release_statuses, status_counts = ubuntu_package_statuses(packages)
    notices = [item for item in as_list(data.get("notices")) if isinstance(item, dict)]
    notice_summaries = ubuntu_notice_summary(notices)
    notice_ids = unique_clean(data.get("notices_ids") or [notice.get("id") for notice in notices])
    patches = as_dict(data.get("patches"))
    patch_links = []
    for package_name, values in patches.items():
        for value in as_list(values):
            text = clean_text(value)
            if text:
                patch_links.append({"package": package_name, "patch": text})
    severity_source = impact_cvss.get("baseSeverity") or data.get("priority")
    mitigation = clean_text(data.get("mitigation"))
    note_text = clean_text([note.get("note") for note in as_list(data.get("notes")) if isinstance(note, dict)])
    notice_instructions = clean_text([notice.get("instructions") for notice in notices])
    remediation = mitigation or notice_instructions or note_text or "See Ubuntu Security Notice"

    return {
        "cve_id": data.get("id") or cve_id,
        "source_os": "ubuntu",
        "source_api": api_name,
        "source_url": url,
        "source_status_code": status_code,
        "api_status": "ok",
        "severity": normalize_severity(severity_source),
        "severity_source": severity_source,
        "priority": data.get("priority"),
        "cvss_score": to_float(cvss3 if isinstance(cvss3, (int, float, str)) else impact_cvss.get("baseScore")),
        "cvss_vector": impact_cvss.get("vectorString"),
        "cvss_version": impact_cvss.get("version"),
        "cvss_metrics": impact_cvss or None,
        "description": clean_text(data.get("description")),
        "ubuntu_description": clean_text(data.get("ubuntu_description")),
        "status": data.get("status"),
        "remediation": remediation,
        "ai_summary": None,
        "published_at": data.get("published"),
        "updated_at": data.get("updated_at"),
        "references": split_references(data.get("references")),
        "official_links": official_ubuntu_links(data.get("id") or cve_id, url, notice_ids),
        "bugs": unique_clean(data.get("bugs") or []),
        "notices": notice_summaries,
        "notices_ids": notice_ids,
        "packages": package_summaries,
        "package_statuses": release_statuses,
        "package_status_counts": status_counts,
        "package_count": len(package_summaries),
        "patches": patches,
        "patch_links": patch_links,
        "patch_count": len(patch_links),
        "notes": [item for item in as_list(data.get("notes")) if isinstance(item, dict)],
        "mitigation": mitigation,
        "tags": data.get("tags") if isinstance(data.get("tags"), dict) else {},
        "provider_fields": {
            "codename": data.get("codename"),
            "has_notices": bool(notice_summaries),
            "has_patches": bool(patch_links),
            "status_counts": status_counts,
        },
    }


def build_failed_cve_record(
    cve_id: str,
    os_name: str,
    exc: Exception,
) -> dict[str, Any]:
    status_code = exc.status_code if isinstance(exc, CveApiError) else None
    api_name = exc.api_name if isinstance(exc, CveApiError) else None
    url = exc.url if isinstance(exc, CveApiError) else None
    body_preview = exc.body_preview if isinstance(exc, CveApiError) else None
    official_links = (
        official_ubuntu_links(cve_id, url or f"https://ubuntu.com/security/cves/{cve_id}.json", [])
        if os_name == "ubuntu"
        else official_rhel_links(cve_id, url or f"https://access.redhat.com/hydra/rest/securitydata/cve/{cve_id}.json", [])
    )
    return {
        "cve_id": cve_id,
        "source_os": os_name,
        "source_api": api_name,
        "source_url": url,
        "source_status_code": status_code,
        "api_status": "not_found" if status_code == 404 else "error",
        "api_error": str(exc),
        "api_error_body_preview": body_preview,
        "severity": "UNKNOWN",
        "severity_source": None,
        "cvss_score": None,
        "cvss_vector": None,
        "description": None,
        "status": None,
        "remediation": None,
        "ai_summary": None,
        "references": [],
        "official_links": official_links,
        "advisories": [],
        "affected_releases": [],
        "affected_packages": [],
        "packages": [],
        "notices": [],
        "patch_links": [],
    }


def classify_status_label(status: Any) -> str:
    value = clean_text(status)
    if not value:
        return "Unknown"
    normalized = value.lower().replace("_", "-").strip()
    if normalized in {"released", "fixed", "resolved"}:
        return "Fixed"
    if normalized in {"not-affected", "not affected", "dne", "does-not-exist"}:
        return "Not affected"
    if normalized in {"ignored", "end-of-life", "end of life"}:
        return "Not affected"
    if normalized in {"deferred", "will-not-fix", "wont-fix"}:
        return "Deferred"
    if normalized in {"needed", "needs-triage", "affected", "vulnerable"}:
        return "Affected"
    if "not affected" in normalized:
        return "Not affected"
    if "ignored" in normalized:
        return "Not affected"
    if "defer" in normalized:
        return "Deferred"
    if "affect" in normalized or "needed" in normalized or "triage" in normalized:
        return "Affected"
    if "fix" in normalized or "release" in normalized:
        return "Fixed"
    return value.title()


def count_status_labels(statuses: list[Any]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for status in statuses:
        label = classify_status_label(status)
        counts[label] = counts.get(label, 0) + 1
    return counts


NO_ATTENTION_STATUS_CATEGORIES = {"fixed", "released", "not_affected", "not_found", "not_listed", "dne", "ignored"}


def normalize_status_category(value: Any) -> str:
    return str(value or "").strip().lower().replace("-", "_").replace(" ", "_")


def status_category_requires_attention(value: Any) -> bool | None:
    category = normalize_status_category(value)
    if category in NO_ATTENTION_STATUS_CATEGORIES:
        return False
    if category in {"affected", "deferred", "unknown", "needed", "needs_triage", "vulnerable"}:
        return True
    return None


def rhel_major(os_version: str) -> str:
    return os_version.split(".", 1)[0]


def release_matches_rhel(os_version: str, value: Any) -> bool:
    text = clean_text(value)
    if not text:
        return False
    major = re.escape(rhel_major(os_version))
    return bool(re.search(rf"\b(?:rhel|linux|el)[ _-]?{major}(?:\b|[._-])", text, re.IGNORECASE))


def build_status_evidence(cve: dict[str, Any], workspace: dict[str, Any]) -> dict[str, Any]:
    os_name = workspace["os"]
    os_version = workspace["os_version"]
    evidence: dict[str, Any] = {
        "cve_id": cve.get("cve_id"),
        "target_os": os_name,
        "target_os_version": os_version,
        "severity": cve.get("severity"),
        "cvss_score": cve.get("cvss_score"),
        "api_status": cve.get("api_status"),
        "source_status_code": cve.get("source_status_code"),
    }

    if cve.get("api_status") == "not_found":
        evidence["status_summary"] = {"Not found": 1}
        evidence["target_statuses"] = []
        return evidence

    if os_name == "ubuntu":
        codename = UBUNTU_CODENAMES.get(os_version)
        statuses = cve.get("package_statuses") or []
        target_statuses = [item for item in statuses if item.get("release") == codename] if codename else []
        all_statuses = [item.get("status") for item in statuses]
        target_status_values = [item.get("status") for item in target_statuses]
        summary = count_status_labels(all_statuses)
        if not target_statuses:
            summary["Not listed"] = summary.get("Not listed", 0) + 1
        evidence.update(
            {
                "ubuntu_codename": codename,
                "status_summary": summary,
                "target_statuses": target_statuses,
                "target_status_summary": count_status_labels(target_status_values) if target_status_values else {"Not listed": 1},
                "notices_ids": cve.get("notices_ids") or [],
                "patch_count": cve.get("patch_count") or 0,
                "package_status_counts": cve.get("package_status_counts") or {},
            }
        )
        return evidence

    major = rhel_major(os_version)
    affected_releases = cve.get("affected_releases") or []
    package_states = cve.get("package_states") or []
    matching_affected = [
        item
        for item in affected_releases
        if release_matches_rhel(os_version, item.get("product_name"))
        or release_matches_rhel(os_version, item.get("cpe"))
        or release_matches_rhel(os_version, item.get("package"))
    ]
    matching_package_states = [
        item
        for item in package_states
        if release_matches_rhel(os_version, item.get("product_name")) or release_matches_rhel(os_version, item.get("cpe"))
    ]
    summary = count_status_labels([item.get("fix_state") for item in package_states])
    if affected_releases:
        summary["Fixed"] = summary.get("Fixed", 0) + len(affected_releases)
    if not matching_affected and not matching_package_states:
        summary["Not listed"] = summary.get("Not listed", 0) + 1
    evidence.update(
        {
            "rhel_major": major,
            "status_summary": summary,
            "target_affected_releases": matching_affected,
            "target_package_states": matching_package_states,
            "target_status_summary": count_status_labels([item.get("fix_state") for item in matching_package_states])
            if matching_package_states
            else ({"Fixed": len(matching_affected)} if matching_affected else {"Not listed": 1}),
            "advisories": cve.get("advisories") or [],
            "affected_release_count": cve.get("affected_release_count") or 0,
            "package_state_count": cve.get("package_state_count") or 0,
        }
    )
    return evidence


def fallback_attention_classification(cve: dict[str, Any], evidence: dict[str, Any]) -> dict[str, Any]:
    if cve.get("api_status") == "not_found":
        status_category = "not_found"
        attention_needed = False
    else:
        target_summary = evidence.get("target_status_summary") or {}
        labels = {str(label).lower() for label in target_summary}
        if labels & {"affected", "deferred"}:
            status_category = "affected" if "affected" in labels else "deferred"
            attention_needed = True
        elif "fixed" in labels:
            status_category = "fixed"
            attention_needed = False
        elif "not affected" in labels:
            status_category = "not_affected"
            attention_needed = False
        elif "not listed" in labels:
            status_category = "not_listed"
            attention_needed = False
        else:
            status_category = "unknown"
            attention_needed = True

    reason = (
        f"Fallback classifier: target status is {status_category}; "
        f"status is the report gate, severity={cve.get('severity')} cvss={cve.get('cvss_score')} is secondary."
    )
    return {
        "provider": "fallback",
        "attention_needed": attention_needed,
        "status_category": status_category,
        "status_summary": evidence.get("status_summary") or {},
        "target_status_summary": evidence.get("target_status_summary") or {},
        "confidence": "medium",
        "reason": reason,
        "recommended_action": cve.get("remediation") if attention_needed else "No report action required.",
    }


def compact_ai_payload(cve: dict[str, Any], evidence: dict[str, Any]) -> dict[str, Any]:
    return {
        "cve_id": cve.get("cve_id"),
        "target": {
            "os": evidence.get("target_os"),
            "version": evidence.get("target_os_version"),
            "ubuntu_codename": evidence.get("ubuntu_codename"),
            "rhel_major": evidence.get("rhel_major"),
        },
        "severity": cve.get("severity"),
        "severity_source": cve.get("severity_source"),
        "cvss_score": cve.get("cvss_score"),
        "api_status": cve.get("api_status"),
        "source_status_code": cve.get("source_status_code"),
        "status_summary": evidence.get("status_summary"),
        "target_status_summary": evidence.get("target_status_summary"),
        "target_statuses": evidence.get("target_statuses") or evidence.get("target_package_states") or [],
        "target_affected_releases": evidence.get("target_affected_releases") or [],
        "advisories": (cve.get("advisories") or [])[:8],
        "notices_ids": (cve.get("notices_ids") or [])[:8],
        "instruction": "Filter by target status first. Do not include fixed, released, ignored, DNE, not found, or not listed CVEs in the report.",
        "description": (cve.get("description") or "")[:1200],
        "remediation": (cve.get("remediation") or "")[:1200],
    }


def parse_json_object(text: str) -> dict[str, Any]:
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        match = re.search(r"\{.*\}", text, re.DOTALL)
        if not match:
            raise
        return json.loads(match.group(0))


async def classify_cve_attention(
    session: aiohttp.ClientSession,
    workspace: dict[str, Any],
    cve: dict[str, Any],
) -> dict[str, Any]:
    workspace = dict(workspace)
    evidence = build_status_evidence(cve, workspace)
    fallback = fallback_attention_classification(cve, evidence)
    key_status = groq_key_status()
    api_key = os.environ.get("GROQ_API_KEY") if key_status["enabled"] else None
    logger.info(
        "CVE status evidence built | cve=%s target=%s/%s api_status=%s status_summary=%s target_status_summary=%s fallback_attention=%s fallback_category=%s",
        cve.get("cve_id"),
        workspace.get("os"),
        workspace.get("os_version"),
        cve.get("api_status"),
        json.dumps(evidence.get("status_summary") or {}, sort_keys=True),
        json.dumps(evidence.get("target_status_summary") or {}, sort_keys=True),
        fallback["attention_needed"],
        fallback["status_category"],
    )
    if not api_key:
        logger.info(
            "Groq CVE classifier skipped | cve=%s reason=GROQ_API_KEY %s fallback_attention=%s fallback_category=%s",
            cve.get("cve_id"),
            key_status["state"],
            fallback["attention_needed"],
            fallback["status_category"],
        )
        cve["attention"] = fallback
        return fallback

    payload = compact_ai_payload(cve, evidence)
    logger.info(
        "Groq CVE classifier request prepared | cve=%s model=%s url=%s payload=%s",
        cve.get("cve_id"),
        GROQ_MODEL,
        GROQ_API_URL,
        json.dumps(payload, ensure_ascii=False, sort_keys=True)[:4000],
    )
    messages = [
        {
            "role": "system",
            "content": (
                "You classify Linux CVE report relevance for a security dashboard. "
                "Return only compact JSON. No markdown. "
                "Use the target OS/version status evidence, not just global CVE severity. "
                "Status is the gate. If the target is not affected, fixed/released, not found, not listed, DNE, ignored, or otherwise not applicable, "
                "attention_needed must be false regardless of CVSS or severity. "
                "Mark attention_needed true only when the target is affected, needed, vulnerable, deferred, needs-triage, or status is truly unknown/unresolved. "
                "Severity and CVSS are secondary context only after target status proves the CVE applies."
            ),
        },
        {
            "role": "user",
            "content": (
                "Classify this CVE for the target. Return JSON with exactly these keys: "
                "attention_needed boolean, status_category string "
                "(affected|fixed|not_affected|deferred|not_found|not_listed|unknown), "
                "confidence string (high|medium|low), reason string, recommended_action string.\n\n"
                f"{json.dumps(payload, ensure_ascii=False)}"
            ),
        },
    ]
    request_payload = {
        "model": GROQ_MODEL,
        "messages": messages,
        "temperature": 0,
        "max_completion_tokens": 500,
    }
    started_at = perf_counter()
    try:
        async with session.post(
            GROQ_API_URL,
            headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
            json=request_payload,
            timeout=aiohttp.ClientTimeout(total=GROQ_TIMEOUT_SECONDS),
        ) as response:
            body = await response.text()
            elapsed_ms = round((perf_counter() - started_at) * 1000, 2)
            logger.info(
                "Groq CVE classifier response received | cve=%s status=%s elapsed_ms=%s body_preview=%s",
                cve.get("cve_id"),
                response.status,
                elapsed_ms,
                body[:1200],
            )
            if response.status >= 400:
                raise RuntimeError(f"Groq returned HTTP {response.status}: {body[:500]}")
            data = json.loads(body)
            content = data["choices"][0]["message"]["content"]
            logger.info(
                "Groq CVE classifier model output | cve=%s content=%s",
                cve.get("cve_id"),
                content[:1200],
            )
            ai = parse_json_object(content)
    except Exception as exc:
        elapsed_ms = round((perf_counter() - started_at) * 1000, 2)
        logger.warning(
            "Groq CVE classifier failed; using fallback | cve=%s elapsed_ms=%s error=%s fallback_attention=%s fallback_category=%s",
            cve.get("cve_id"),
            elapsed_ms,
            exc,
            fallback["attention_needed"],
            fallback["status_category"],
        )
        cve["attention"] = fallback
        return fallback

    status_category = normalize_status_category(ai.get("status_category") or fallback["status_category"])
    category_attention = status_category_requires_attention(status_category)
    attention_needed = bool(ai.get("attention_needed"))
    if category_attention is not None and attention_needed != category_attention:
        logger.warning(
            "Groq CVE classifier normalized inconsistent status | cve=%s ai_attention=%s ai_category=%s normalized_attention=%s",
            cve.get("cve_id"),
            attention_needed,
            status_category,
            category_attention,
        )
        attention_needed = category_attention

    result = {
        "provider": "groq",
        "model": GROQ_MODEL,
        "attention_needed": attention_needed,
        "status_category": status_category,
        "status_summary": evidence.get("status_summary") or {},
        "target_status_summary": evidence.get("target_status_summary") or {},
        "confidence": ai.get("confidence") or "low",
        "reason": clean_text(ai.get("reason")) or fallback["reason"],
        "recommended_action": (clean_text(ai.get("recommended_action")) or fallback["recommended_action"])
        if attention_needed
        else "No report action required.",
    }
    cve["attention"] = result
    if result["recommended_action"]:
        cve["remediation"] = result["recommended_action"]
    logger.info(
        "Groq CVE classification parsed | cve=%s attention=%s status_category=%s confidence=%s target_status_summary=%s reason=%s",
        cve.get("cve_id"),
        result["attention_needed"],
        result["status_category"],
        result["confidence"],
        json.dumps(result["target_status_summary"], sort_keys=True),
        result["reason"],
    )
    return result


async def query_cve(session: aiohttp.ClientSession, os_name: str, cve_id: str) -> dict[str, Any]:
    if os_name == "ubuntu":
        url = f"https://ubuntu.com/security/cves/{cve_id}.json"
        api_name = "Ubuntu Security CVE API"
    else:
        url = f"https://access.redhat.com/hydra/rest/securitydata/cve/{cve_id}.json"
        api_name = "Red Hat Security Data API"

    started_at = perf_counter()
    logger.info(
        "CVE API request started | cve=%s os=%s api=%s url=%s",
        cve_id,
        os_name,
        api_name,
        url,
    )

    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=20)) as response:
            elapsed_ms = round((perf_counter() - started_at) * 1000, 2)
            logger.info(
                "CVE API response received | cve=%s os=%s api=%s status=%s elapsed_ms=%s url=%s",
                cve_id,
                os_name,
                api_name,
                response.status,
                elapsed_ms,
                url,
            )
            body = await response.text()
            status_code = response.status
            if status_code >= 400:
                raise CveApiError(
                    f"Upstream returned HTTP {status_code}",
                    status_code=status_code,
                    api_name=api_name,
                    url=url,
                    body_preview=body[:1000],
                )
            data = json.loads(body)
    except Exception:
        elapsed_ms = round((perf_counter() - started_at) * 1000, 2)
        logger.exception(
            "CVE API request failed | cve=%s os=%s api=%s elapsed_ms=%s url=%s",
            cve_id,
            os_name,
            api_name,
            elapsed_ms,
            url,
        )
        raise

    if os_name == "ubuntu":
        result = normalize_ubuntu_cve(data, cve_id, api_name, url, status_code)
        logger.info(
            "CVE API parsed | cve=%s os=%s api=%s severity=%s cvss=%s status=%s package_count=%s notice_count=%s patch_count=%s",
            result["cve_id"],
            os_name,
            api_name,
            result["severity"],
            result["cvss_score"],
            result["status"],
            len(result["packages"]),
            len(result["notices"]),
            result["patch_count"],
        )
        return result

    result = normalize_rhel_cve(data, cve_id, api_name, url, status_code)
    logger.info(
        "CVE API parsed | cve=%s os=%s api=%s severity=%s cvss=%s advisory=%s affected_release_count=%s package_state_count=%s",
        result["cve_id"],
        os_name,
        api_name,
        result["severity"],
        result["cvss_score"],
        result["status"],
        result["affected_release_count"],
        result["package_state_count"],
    )
    return result


def severity_counts(all_cves: list[dict[str, Any]]) -> dict[str, int]:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "unknown": 0}
    for item in all_cves:
        key = normalize_severity(item.get("severity")).lower()
        counts[key if key in counts else "unknown"] += 1
    return counts


async def get_workspace_for_researcher(db: aiosqlite.Connection, workspace_id: int, user_id: int) -> aiosqlite.Row:
    cursor = await db.execute(
        "SELECT * FROM workspaces WHERE id = ? AND researcher_id = ?",
        (workspace_id, user_id),
    )
    workspace = await cursor.fetchone()
    if not workspace:
        raise api_error(404, "Not found", "Workspace not found")
    return workspace


async def init_db() -> None:
    UPLOAD_DIR.mkdir(exist_ok=True)
    async with db_connect() as db:
        await db.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              username TEXT UNIQUE NOT NULL,
              password_hash TEXT NOT NULL,
              role TEXT NOT NULL CHECK(role IN ('admin', 'researcher', 'viewer')),
              created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS workspaces (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              researcher_id INTEGER NOT NULL REFERENCES users(id),
              name TEXT NOT NULL,
              ip TEXT NOT NULL,
              os TEXT NOT NULL,
              os_version TEXT NOT NULL,
              scan_date DATE NOT NULL,
              created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS scan_files (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              workspace_id INTEGER NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
              filename TEXT NOT NULL,
              filepath TEXT NOT NULL,
              uploaded_at DATETIME DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS reports (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              workspace_id INTEGER REFERENCES workspaces(id) ON DELETE SET NULL,
              version INTEGER NOT NULL DEFAULT 1,
              ip TEXT NOT NULL,
              os TEXT NOT NULL,
              os_version TEXT NOT NULL,
              scan_date DATE NOT NULL,
              cve_summary TEXT NOT NULL,
              cve_count_critical INTEGER DEFAULT 0,
              cve_count_high INTEGER DEFAULT 0,
              cve_count_medium INTEGER DEFAULT 0,
              cve_count_low INTEGER DEFAULT 0,
              cve_count_unknown INTEGER DEFAULT 0,
              saved_at DATETIME DEFAULT CURRENT_TIMESTAMP,
              saved_by INTEGER REFERENCES users(id)
            );

            CREATE TABLE IF NOT EXISTS sessions (
              token TEXT PRIMARY KEY,
              user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
              created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            );
            """
        )
        cursor = await db.execute("SELECT COUNT(*) AS count FROM users WHERE role = 'admin'")
        admin_count = (await cursor.fetchone())["count"]
        if admin_count == 0:
            await db.execute(
                "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
                ("admin", hash_password("admin"), "admin"),
            )
        await db.commit()


@app.on_event("startup")
async def on_startup() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
    )
    await init_db()
    key_status = groq_key_status()
    logger.info("Server running at http://localhost:8000")
    logger.info(
        "Environment file status | path=%s found=%s loaded=%s skipped_existing=%s",
        ENV_FILE_STATUS["path"],
        ENV_FILE_STATUS["found"],
        ",".join(ENV_FILE_STATUS["loaded"]) if ENV_FILE_STATUS["loaded"] else "-",
        ",".join(ENV_FILE_STATUS["skipped"]) if ENV_FILE_STATUS["skipped"] else "-",
    )
    logger.info(
        "Groq configuration | enabled=%s key_state=%s key=%s model=%s url=%s timeout_seconds=%s",
        key_status["enabled"],
        key_status["state"],
        key_status["masked"],
        GROQ_MODEL,
        GROQ_API_URL,
        GROQ_TIMEOUT_SECONDS,
    )
    logger.info(
        "CVE pipeline config | delay_seconds=%s groq_enabled=%s groq_model=%s groq_url=%s",
        CVE_REQUEST_DELAY_SECONDS,
        key_status["enabled"],
        GROQ_MODEL,
        GROQ_API_URL,
    )


@app.get("/", response_class=HTMLResponse)
async def index(request: Request) -> HTMLResponse:
    return templates.TemplateResponse(request=request, name="index.html", context={})


@app.post("/api/auth/login")
async def login(payload: LoginPayload, response: Response) -> dict[str, Any]:
    async with db_connect() as db:
        cursor = await db.execute("SELECT * FROM users WHERE username = ?", (payload.username,))
        user = await cursor.fetchone()
        if not user or not verify_password(payload.password, user["password_hash"]):
            raise api_error(401, "Unauthorized", "Invalid username or password")

        raw_token = secrets.token_hex(32)
        await db.execute("INSERT INTO sessions (token, user_id) VALUES (?, ?)", (raw_token, user["id"]))
        await db.commit()

    response.set_cookie(
        SESSION_COOKIE,
        sign_session_token(raw_token),
        httponly=True,
        samesite="lax",
    )
    return {"id": user["id"], "username": user["username"], "role": user["role"]}


@app.post("/api/auth/logout")
async def logout(request: Request, response: Response) -> dict[str, str]:
    signed_token = request.cookies.get(SESSION_COOKIE)
    token = unsign_session_token(signed_token) if signed_token else None
    if token:
        async with db_connect() as db:
            await db.execute("DELETE FROM sessions WHERE token = ?", (token,))
            await db.commit()
    response.delete_cookie(SESSION_COOKIE)
    return {"status": "ok"}


@app.get("/api/auth/me")
async def me(user: dict[str, Any] = Depends(get_current_user)) -> dict[str, Any]:
    return {"id": user["id"], "username": user["username"], "role": user["role"]}


@app.get("/api/admin/users")
async def list_users(_: dict[str, Any] = Depends(require_role("admin"))) -> list[dict[str, Any]]:
    async with db_connect() as db:
        cursor = await db.execute(
            "SELECT id, username, role, created_at FROM users ORDER BY created_at DESC, username ASC"
        )
        rows = await cursor.fetchall()
    return [dict(row) for row in rows]


@app.post("/api/admin/users")
async def create_user(
    payload: UserCreatePayload,
    _: dict[str, Any] = Depends(require_role("admin")),
) -> dict[str, Any]:
    role = validate_role(payload.role, allow_admin=False)
    if not payload.username.strip() or not payload.password:
        raise api_error(422, "Validation failed", "Username and password are required")
    try:
        async with db_connect() as db:
            cursor = await db.execute(
                "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
                (payload.username.strip(), hash_password(payload.password), role),
            )
            await db.commit()
            return {"id": cursor.lastrowid, "username": payload.username.strip(), "role": role}
    except aiosqlite.IntegrityError:
        raise api_error(422, "Validation failed", "Username already exists")


@app.delete("/api/admin/users/{user_id}")
async def delete_user(
    user_id: int,
    current_user: dict[str, Any] = Depends(require_role("admin")),
) -> dict[str, str]:
    if user_id == current_user["id"]:
        raise api_error(422, "Validation failed", "You cannot delete your own account")
    async with db_connect() as db:
        cursor = await db.execute("DELETE FROM users WHERE id = ? AND role != 'admin'", (user_id,))
        await db.commit()
        if cursor.rowcount == 0:
            raise api_error(404, "Not found", "User not found or cannot be deleted")
    return {"status": "ok"}


@app.post("/api/admin/users/{user_id}/reset")
async def reset_password(
    user_id: int,
    payload: ResetPasswordPayload,
    _: dict[str, Any] = Depends(require_role("admin")),
) -> dict[str, str]:
    if not payload.new_password:
        raise api_error(422, "Validation failed", "New password is required")
    async with db_connect() as db:
        cursor = await db.execute(
            "UPDATE users SET password_hash = ? WHERE id = ?",
            (hash_password(payload.new_password), user_id),
        )
        await db.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))
        await db.commit()
        if cursor.rowcount == 0:
            raise api_error(404, "Not found", "User not found")
    return {"status": "ok"}


@app.get("/api/workspaces")
async def list_workspaces(user: dict[str, Any] = Depends(require_role("researcher"))) -> list[dict[str, Any]]:
    async with db_connect() as db:
        cursor = await db.execute(
            """
            SELECT workspaces.*,
                   COUNT(DISTINCT scan_files.id) AS file_count,
                   COUNT(DISTINCT reports.id) AS report_count
            FROM workspaces
            LEFT JOIN scan_files ON scan_files.workspace_id = workspaces.id
            LEFT JOIN reports ON reports.workspace_id = workspaces.id
            WHERE workspaces.researcher_id = ?
            GROUP BY workspaces.id
            ORDER BY workspaces.created_at DESC
            """,
            (user["id"],),
        )
        rows = await cursor.fetchall()
    return [dict(row) for row in rows]


@app.post("/api/workspaces")
async def create_workspace(
    payload: WorkspaceCreatePayload,
    user: dict[str, Any] = Depends(require_role("researcher")),
) -> dict[str, Any]:
    validate_workspace_input(payload)
    name = workspace_name(payload.ip, payload.os, payload.os_version, payload.scan_date)
    async with db_connect() as db:
        cursor = await db.execute(
            """
            INSERT INTO workspaces (researcher_id, name, ip, os, os_version, scan_date)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (user["id"], name, payload.ip, payload.os, payload.os_version, payload.scan_date.isoformat()),
        )
        await db.commit()
        workspace_id = cursor.lastrowid
    return {
        "id": workspace_id,
        "researcher_id": user["id"],
        "name": name,
        "ip": payload.ip,
        "os": payload.os,
        "os_version": payload.os_version,
        "scan_date": payload.scan_date.isoformat(),
    }


@app.get("/api/workspaces/{workspace_id}")
async def get_workspace(
    workspace_id: int,
    user: dict[str, Any] = Depends(require_role("researcher")),
) -> dict[str, Any]:
    async with db_connect() as db:
        workspace = await get_workspace_for_researcher(db, workspace_id, user["id"])
        cursor = await db.execute("SELECT * FROM scan_files WHERE workspace_id = ? ORDER BY uploaded_at DESC", (workspace_id,))
        files = [dict(row) for row in await cursor.fetchall()]
        cursor = await db.execute(
            "SELECT id, version, saved_at FROM reports WHERE workspace_id = ? ORDER BY version DESC",
            (workspace_id,),
        )
        reports = [dict(row) for row in await cursor.fetchall()]
    return {**dict(workspace), "files": files, "reports": reports}


@app.get("/api/workspaces/{workspace_id}/cves")
async def list_workspace_cves(
    workspace_id: int,
    user: dict[str, Any] = Depends(require_role("researcher")),
) -> dict[str, Any]:
    async with db_connect() as db:
        await get_workspace_for_researcher(db, workspace_id, user["id"])
        cursor = await db.execute("SELECT * FROM scan_files WHERE workspace_id = ? ORDER BY uploaded_at ASC", (workspace_id,))
        files = [dict(row) for row in await cursor.fetchall()]

    logger.info(
        "Local CVE extraction requested | workspace_id=%s user_id=%s username=%s file_count=%s",
        workspace_id,
        user["id"],
        user["username"],
        len(files),
    )
    result = await collect_file_cves(workspace_id, files)
    logger.info(
        "Local CVE extraction completed | workspace_id=%s unique_cve_count=%s",
        workspace_id,
        result["total"],
    )
    return result


@app.delete("/api/workspaces/{workspace_id}")
async def delete_workspace(
    workspace_id: int,
    user: dict[str, Any] = Depends(require_role("researcher")),
) -> dict[str, str]:
    async with db_connect() as db:
        workspace = await get_workspace_for_researcher(db, workspace_id, user["id"])
        cursor = await db.execute("SELECT filepath FROM scan_files WHERE workspace_id = ?", (workspace["id"],))
        filepaths = [row["filepath"] for row in await cursor.fetchall()]
        await db.execute("DELETE FROM workspaces WHERE id = ?", (workspace["id"],))
        await db.commit()
    for relative in filepaths:
        path = (UPLOAD_DIR / relative).resolve()
        if UPLOAD_DIR.resolve() in path.parents and path.exists():
            path.unlink(missing_ok=True)
    PARSE_CACHE.pop(workspace_id, None)
    return {"status": "ok"}


@app.post("/api/workspaces/{workspace_id}/files")
async def upload_files(
    workspace_id: int,
    files: list[UploadFile] = File(...),
    user: dict[str, Any] = Depends(require_role("researcher")),
) -> dict[str, Any]:
    results = []
    async with db_connect() as db:
        await get_workspace_for_researcher(db, workspace_id, user["id"])
        workspace_dir = UPLOAD_DIR / str(workspace_id)
        workspace_dir.mkdir(exist_ok=True)

        for upload in files:
            suffix = Path(upload.filename or "").suffix.lower()
            if suffix not in ALLOWED_UPLOAD_SUFFIXES:
                results.append({"filename": upload.filename, "status": "error", "message": "Unsupported file type"})
                continue

            content = await upload.read()
            if len(content) > MAX_UPLOAD_BYTES:
                results.append({"filename": upload.filename, "status": "error", "message": "File exceeds 10MB"})
                continue

            safe_name = re.sub(r"[^A-Za-z0-9_.-]+", "_", Path(upload.filename or "scan.txt").name)
            stored_name = f"{secrets.token_hex(8)}_{safe_name}"
            relative_path = f"{workspace_id}/{stored_name}"
            destination = workspace_dir / stored_name
            destination.write_bytes(content)

            cursor = await db.execute(
                "INSERT INTO scan_files (workspace_id, filename, filepath) VALUES (?, ?, ?)",
                (workspace_id, upload.filename or safe_name, relative_path),
            )
            results.append(
                {
                    "id": cursor.lastrowid,
                    "filename": upload.filename or safe_name,
                    "filepath": relative_path,
                    "status": "ok",
                }
            )
        await db.commit()
    PARSE_CACHE.pop(workspace_id, None)
    return {"files": results}


@app.delete("/api/workspaces/{workspace_id}/files/{file_id}")
async def delete_file(
    workspace_id: int,
    file_id: int,
    user: dict[str, Any] = Depends(require_role("researcher")),
) -> dict[str, str]:
    async with db_connect() as db:
        await get_workspace_for_researcher(db, workspace_id, user["id"])
        cursor = await db.execute(
            "SELECT filepath FROM scan_files WHERE id = ? AND workspace_id = ?",
            (file_id, workspace_id),
        )
        row = await cursor.fetchone()
        if not row:
            raise api_error(404, "Not found", "File not found")
        await db.execute("DELETE FROM scan_files WHERE id = ?", (file_id,))
        await db.commit()

    path = (UPLOAD_DIR / row["filepath"]).resolve()
    if UPLOAD_DIR.resolve() in path.parents and path.exists():
        path.unlink(missing_ok=True)
    PARSE_CACHE.pop(workspace_id, None)
    return {"status": "ok"}


@app.post("/api/workspaces/{workspace_id}/parse")
async def parse_workspace(
    workspace_id: int,
    user: dict[str, Any] = Depends(require_role("researcher")),
) -> StreamingResponse:
    async with db_connect() as db:
        workspace = await get_workspace_for_researcher(db, workspace_id, user["id"])
        workspace = dict(workspace)
        cursor = await db.execute("SELECT * FROM scan_files WHERE workspace_id = ? ORDER BY uploaded_at ASC", (workspace_id,))
        files = [dict(row) for row in await cursor.fetchall()]

    logger.info(
        "CVE parse job accepted | workspace_id=%s workspace_name=%s ip=%s os=%s os_version=%s scan_date=%s user_id=%s username=%s file_count=%s",
        workspace_id,
        workspace["name"],
        workspace["ip"],
        workspace["os"],
        workspace["os_version"],
        workspace["scan_date"],
        user["id"],
        user["username"],
        len(files),
    )

    async def stream():
        all_ids: set[str] = set()
        for item in files:
            absolute = UPLOAD_DIR / item["filepath"]
            if absolute.exists():
                logger.info(
                    "Parsing scan file for CVEs | workspace_id=%s file_id=%s filename=%s filepath=%s",
                    workspace_id,
                    item["id"],
                    item["filename"],
                    item["filepath"],
                )
                parsed = await asyncio.to_thread(parse_nmap_file, str(absolute))
                logger.info(
                    "Scan file parsed | workspace_id=%s file_id=%s filename=%s cve_count=%s",
                    workspace_id,
                    item["id"],
                    item["filename"],
                    len(parsed),
                )
                all_ids.update(parsed)
            else:
                logger.warning(
                    "Scan file missing on disk | workspace_id=%s file_id=%s filename=%s filepath=%s",
                    workspace_id,
                    item["id"],
                    item["filename"],
                    item["filepath"],
                )

        cve_ids = sorted(all_ids)
        all_cves: list[dict[str, Any]] = []
        parse_errors: list[dict[str, Any]] = []
        total = len(cve_ids)
        logger.info(
            "CVE parse job deduplicated | workspace_id=%s unique_cve_count=%s cves=%s",
            workspace_id,
            total,
            ",".join(cve_ids) if cve_ids else "-",
        )

        if total == 0:
            summary = {"all_cves": [], "needs_attention": [], "filtered_out": [], "reviewed_total": 0, "parse_errors": []}
            PARSE_CACHE[workspace_id] = summary
            logger.info("CVE parse job completed | workspace_id=%s total=0 needs_attention=0", workspace_id)
            yield "event: done\n"
            yield f"data: {json.dumps({'total': 0, 'needs_attention': 0, 'filtered_out': 0, 'classifier': 'groq' if groq_key_status()['enabled'] else 'fallback', 'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'unknown': 0})}\n\n"
            return

        async with aiohttp.ClientSession() as session:
            for index, cve_id in enumerate(cve_ids, start=1):
                try:
                    logger.info(
                        "CVE API queue item | workspace_id=%s current=%s total=%s cve=%s",
                        workspace_id,
                        index,
                        total,
                        cve_id,
                    )
                    yield "event: progress\n"
                    yield f"data: {json.dumps({'current': index, 'total': total, 'cve_id': cve_id, 'status': 'running', 'message': 'Checking CVE API and AI status gate'})}\n\n"
                    cve_data = await query_cve(session, workspace["os"], cve_id)
                    classification = await classify_cve_attention(session, workspace, cve_data)
                    all_cves.append(cve_data)
                    logger.info(
                        "CVE API queue item completed | workspace_id=%s current=%s total=%s cve=%s severity=%s attention=%s status_category=%s classifier=%s confidence=%s",
                        workspace_id,
                        index,
                        total,
                        cve_id,
                        cve_data["severity"],
                        classification["attention_needed"],
                        classification["status_category"],
                        classification.get("provider"),
                        classification.get("confidence"),
                    )
                    yield "event: progress\n"
                    yield f"data: {json.dumps({'current': index, 'total': total, 'cve_id': cve_id, 'status': 'ok', 'severity': cve_data['severity'], 'attention_needed': classification['attention_needed'], 'status_category': classification['status_category'], 'classifier': classification.get('provider'), 'confidence': classification.get('confidence'), 'reason': classification.get('reason'), 'status_summary': classification.get('status_summary'), 'target_status_summary': classification.get('target_status_summary')})}\n\n"
                except Exception as exc:
                    logger.warning(
                        "CVE API queue item skipped | workspace_id=%s current=%s total=%s cve=%s error=%s",
                        workspace_id,
                        index,
                        total,
                        cve_id,
                        exc,
                    )
                    error = {
                        "cve_id": cve_id,
                        "message": str(exc),
                        "source_status_code": exc.status_code if isinstance(exc, CveApiError) else None,
                        "source_url": exc.url if isinstance(exc, CveApiError) else None,
                        "api_status": "not_found"
                        if isinstance(exc, CveApiError) and exc.status_code == 404
                        else "error",
                    }
                    parse_errors.append(error)
                    failed_record = build_failed_cve_record(cve_id, workspace["os"], exc)
                    classification = await classify_cve_attention(session, workspace, failed_record)
                    all_cves.append(failed_record)
                    yield "event: progress\n"
                    yield f"data: {json.dumps({'current': index, 'total': total, 'cve_id': cve_id, 'status': 'error', 'message': str(exc), 'attention_needed': classification['attention_needed'], 'status_category': classification['status_category'], 'classifier': classification.get('provider'), 'confidence': classification.get('confidence'), 'reason': classification.get('reason'), 'status_summary': classification.get('status_summary'), 'target_status_summary': classification.get('target_status_summary')})}\n\n"
                if index < total:
                    logger.info(
                        "CVE pipeline rate limit wait | workspace_id=%s completed=%s remaining=%s delay_seconds=%s",
                        workspace_id,
                        index,
                        total - index,
                        CVE_REQUEST_DELAY_SECONDS,
                    )
                    await asyncio.sleep(CVE_REQUEST_DELAY_SECONDS)

        needs_attention = [
            item
            for item in all_cves
            if (item.get("attention") or {}).get("attention_needed") is True
            and status_category_requires_attention((item.get("attention") or {}).get("status_category")) is not False
        ]
        filtered_out = [
            {
                "cve_id": item.get("cve_id"),
                "severity": item.get("severity"),
                "cvss_score": item.get("cvss_score"),
                "api_status": item.get("api_status"),
                "attention": item.get("attention"),
            }
            for item in all_cves
            if item not in needs_attention
        ]
        summary = {
            "all_cves": needs_attention,
            "needs_attention": needs_attention,
            "filtered_out": filtered_out,
            "reviewed_total": len(all_cves),
            "parse_errors": parse_errors,
        }
        PARSE_CACHE[workspace_id] = summary
        counts = severity_counts(needs_attention)
        done_payload = {
            "total": total,
            "needs_attention": len(needs_attention),
            "filtered_out": len(filtered_out),
            "classifier": "groq" if groq_key_status()["enabled"] else "fallback",
            "critical": counts["critical"],
            "high": counts["high"],
            "medium": counts["medium"],
            "low": counts["low"],
            "unknown": counts["unknown"],
        }
        logger.info(
            "CVE parse job completed | workspace_id=%s total=%s needs_attention=%s filtered_out=%s critical=%s high=%s medium=%s low=%s unknown=%s errors=%s",
            workspace_id,
            total,
            len(needs_attention),
            len(filtered_out),
            counts["critical"],
            counts["high"],
            counts["medium"],
            counts["low"],
            counts["unknown"],
            len(parse_errors),
        )
        yield "event: done\n"
        yield f"data: {json.dumps(done_payload)}\n\n"

    return StreamingResponse(stream(), media_type="text/event-stream")


@app.post("/api/workspaces/{workspace_id}/save")
async def save_report(
    workspace_id: int,
    user: dict[str, Any] = Depends(require_role("researcher")),
) -> dict[str, Any]:
    parsed = PARSE_CACHE.get(workspace_id)
    if not parsed:
        raise api_error(422, "Validation failed", "Run Classify before saving a report")
    async with db_connect() as db:
        workspace = await get_workspace_for_researcher(db, workspace_id, user["id"])
        cursor = await db.execute("SELECT * FROM scan_files WHERE workspace_id = ? ORDER BY uploaded_at ASC", (workspace_id,))
        files = [dict(row) for row in await cursor.fetchall()]

    scan_summary = await collect_file_cves(workspace_id, files)
    report_summary = {
        "all_cves": parsed.get("needs_attention", []),
        "needs_attention": parsed.get("needs_attention", []),
        "services": scan_summary.get("services", []),
        "service_total": scan_summary.get("service_total", 0),
        "results": scan_summary.get("results", []),
        "result_total": scan_summary.get("result_total", 0),
        "applications": scan_summary.get("applications", []),
        "application_total": scan_summary.get("application_total", 0),
        "parse_errors": parsed.get("parse_errors", []),
        "reviewed_total": parsed.get("reviewed_total", len(parsed.get("all_cves", []))),
        "filtered_out_count": len(parsed.get("filtered_out", [])),
        "classifier": "groq" if groq_key_status()["enabled"] else "fallback",
        "ai_cross_verification": groq_key_status()["enabled"],
        "report_policy": "status-first attention-needed only after classifier review",
    }
    counts = severity_counts(report_summary["all_cves"])

    async with db_connect() as db:
        cursor = await db.execute("SELECT COALESCE(MAX(version), 0) + 1 AS next_version FROM reports WHERE workspace_id = ?", (workspace_id,))
        version = (await cursor.fetchone())["next_version"]
        cursor = await db.execute(
            """
            INSERT INTO reports (
              workspace_id, version, ip, os, os_version, scan_date, cve_summary,
              cve_count_critical, cve_count_high, cve_count_medium, cve_count_low,
              cve_count_unknown, saved_by
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                workspace_id,
                version,
                workspace["ip"],
                workspace["os"],
                workspace["os_version"],
                workspace["scan_date"],
                json.dumps(report_summary),
                counts["critical"],
                counts["high"],
                counts["medium"],
                counts["low"],
                counts["unknown"],
                user["id"],
            ),
        )
        await db.commit()
    return {"id": cursor.lastrowid, "version": version, **counts}


@app.get("/api/reports")
async def list_reports(
    ip: str = "",
    os: str = "",
    date: str = "",
    sort: str = "saved_at",
    order: str = "desc",
    page: int = 1,
    _: dict[str, Any] = Depends(require_role("researcher", "viewer")),
) -> dict[str, Any]:
    sort_map = {
        "saved_at": "reports.saved_at",
        "scan_date": "reports.scan_date",
        "cve_count": "(reports.cve_count_critical + reports.cve_count_high + reports.cve_count_medium + reports.cve_count_low + reports.cve_count_unknown)",
    }
    sort_sql = sort_map.get(sort, sort_map["saved_at"])
    order_sql = "ASC" if order.lower() == "asc" else "DESC"
    page = max(page, 1)
    offset = (page - 1) * 10

    clauses = []
    params: list[Any] = []
    if ip:
        clauses.append("reports.ip LIKE ?")
        params.append(f"%{ip}%")
    if os in OS_VERSIONS:
        clauses.append("reports.os = ?")
        params.append(os)
    if date:
        clauses.append("reports.scan_date = ?")
        params.append(date)
    where_sql = f"WHERE {' AND '.join(clauses)}" if clauses else ""

    async with db_connect() as db:
        cursor = await db.execute(f"SELECT COUNT(*) AS count FROM reports {where_sql}", params)
        total = (await cursor.fetchone())["count"]
        cursor = await db.execute(
            f"""
            SELECT reports.id, reports.workspace_id, reports.version, reports.ip, reports.os,
                   reports.os_version, reports.scan_date, reports.saved_at,
                   reports.cve_count_critical, reports.cve_count_high,
                   reports.cve_count_medium, reports.cve_count_low,
                   reports.cve_count_unknown,
                   COALESCE(workspaces.name, reports.ip || ' - ' || reports.os || ' ' || reports.os_version || ' - ' || reports.scan_date) AS workspace_name
            FROM reports
            LEFT JOIN workspaces ON workspaces.id = reports.workspace_id
            {where_sql}
            ORDER BY {sort_sql} {order_sql}
            LIMIT 10 OFFSET ?
            """,
            [*params, offset],
        )
        rows = await cursor.fetchall()
    return {"items": [dict(row) for row in rows], "page": page, "total": total, "per_page": 10}


@app.get("/api/reports/{report_id}")
async def get_report(
    report_id: int,
    _: dict[str, Any] = Depends(require_role("researcher", "viewer")),
) -> dict[str, Any]:
    async with db_connect() as db:
        cursor = await db.execute(
            """
            SELECT reports.*, users.username AS saved_by_username,
                   COALESCE(workspaces.name, reports.ip || ' - ' || reports.os || ' ' || reports.os_version || ' - ' || reports.scan_date) AS workspace_name
            FROM reports
            LEFT JOIN users ON users.id = reports.saved_by
            LEFT JOIN workspaces ON workspaces.id = reports.workspace_id
            WHERE reports.id = ?
            """,
            (report_id,),
        )
        row = await cursor.fetchone()
        files: list[dict[str, Any]] = []
        if row:
            cursor = await db.execute("SELECT * FROM scan_files WHERE workspace_id = ? ORDER BY uploaded_at ASC", (row["workspace_id"],))
            files = [dict(file_row) for file_row in await cursor.fetchall()]
    if not row:
        raise api_error(404, "Not found", "Report not found")
    report = dict(row)
    report["cve_summary"] = json.loads(report["cve_summary"])
    if any(key not in report["cve_summary"] for key in ("services", "results", "applications")) and files:
        scan_summary = await collect_file_cves(report["workspace_id"], files)
        report["cve_summary"]["services"] = scan_summary.get("services", [])
        report["cve_summary"]["service_total"] = scan_summary.get("service_total", 0)
        report["cve_summary"]["results"] = scan_summary.get("results", [])
        report["cve_summary"]["result_total"] = scan_summary.get("result_total", 0)
        report["cve_summary"]["applications"] = scan_summary.get("applications", [])
        report["cve_summary"]["application_total"] = scan_summary.get("application_total", 0)
    return report

