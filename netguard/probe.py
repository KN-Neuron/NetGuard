"""Active network probes used by the posture checks.

Each probe is defensive: it returns a structured "unavailable" result rather
than raising, so a missing tool, a blocked port or a captive portal never
crashes the monitor. The probe layer is also the seam used by the demo
scenarios, which substitute a simulated implementation.
"""

from __future__ import annotations

import os
import socket
import ssl
import subprocess
import tempfile
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

try:  # requests is optional; DoH/HTTP probes degrade to SKIP without it
    import requests
except Exception:  # pragma: no cover - import guard
    requests = None  # type: ignore


# Substrings that identify well-known public certificate authorities. Used to
# distinguish a publicly-trusted certificate from a private/interception CA.
PUBLIC_CA_HINTS = (
    "digicert", "lets encrypt", "isrg", "google trust", "gts", "sectigo",
    "comodo", "globalsign", "amazon", "microsoft", "cloudflare", "godaddy",
    "starfield", "entrust", "dtrust", "certum", "actalis", "buypass",
    "ssl.com", "securetrust", "quovadis", "swisssign", "izenpe", "naver",
    "telia", "t-systems", "secom", "harica", "firmaprofesional", "vtrus",
    "wotrus", "chunghwa", "hongkong post", "twca", "e-szigno", "netlock",
    "disig", "camerfirma", "thawte", "verisign", "geotrust", "rapidssl",
)


@dataclass
class TLSPeer:
    """What we learned by performing a TLS handshake to a test host."""

    host: str = ""
    available: bool = False
    validated: bool = False
    error: str = ""
    subject: str = ""
    issuer: str = ""
    issuer_org: str = ""
    self_signed: bool = False
    not_after: str = ""

    @property
    def issuer_is_public_ca(self) -> bool:
        blob = f"{self.issuer} {self.issuer_org}".lower()
        return any(hint in blob for hint in PUBLIC_CA_HINTS)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "host": self.host,
            "available": self.available,
            "validated": self.validated,
            "error": self.error,
            "subject": self.subject,
            "issuer": self.issuer,
            "issuer_org": self.issuer_org,
            "issuer_is_public_ca": self.issuer_is_public_ca,
            "self_signed": self.self_signed,
            "not_after": self.not_after,
        }


@dataclass
class HttpResponse:
    url: str = ""
    status: int = 0
    headers: Dict[str, str] = field(default_factory=dict)
    body: str = ""
    final_url: str = ""
    location: str = ""
    error: str = ""
    ok: bool = False

    def header(self, name: str) -> str:
        return self.headers.get(name.lower(), "")


class Probes:
    """Real probes backed by the OS resolver, OpenSSL and HTTP(S)."""

    def __init__(self, config) -> None:
        self.config = config

    # -- DNS ---------------------------------------------------------------
    def resolve(self, host: str) -> List[str]:
        """Resolve ``host`` with the system resolver; [] means no answer."""
        try:
            infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
        except (socket.gaierror, OSError):
            return []
        return sorted({info[4][0] for info in infos})

    def doh_resolve(self, host: str) -> Optional[List[str]]:
        """Resolve ``host`` over DNS-over-HTTPS (trusted, encrypted).

        Returns None when DoH is unavailable so callers can mark the check as
        SKIP instead of producing a false verdict.
        """
        if requests is None or not self.config.use_doh:
            return None
        for endpoint in self.config.doh_endpoints:
            try:
                resp = requests.get(
                    endpoint,
                    params={"name": host, "type": "A"},
                    headers={"accept": "application/dns-json"},
                    timeout=self.config.dns_timeout,
                )
                if resp.status_code != 200:
                    continue
                payload = resp.json()
                answers = [
                    str(a.get("data", ""))
                    for a in payload.get("Answer", [])
                    if a.get("type") == 1 and a.get("data")
                ]
                return sorted(set(answers))
            except Exception:
                continue
        return None

    # -- TLS ---------------------------------------------------------------
    def tls_peer(self, host: str, port: int = 443) -> TLSPeer:
        """Perform a TLS handshake and describe the presented certificate."""
        peer = TLSPeer(host=host)
        pem: Optional[str] = None

        verified_ctx = ssl.create_default_context()
        try:
            with socket.create_connection((host, port), timeout=self.config.connect_timeout) as sock:
                with verified_ctx.wrap_socket(sock, server_hostname=host) as tls:
                    pem = ssl.DER_cert_to_PEM_cert(tls.getpeercert(binary_form=True))
                    peer.validated = True
                    peer.available = True
        except ssl.SSLCertVerificationError as exc:
            peer.error = str(exc)
            peer.validated = False
        except (socket.timeout, OSError) as exc:
            peer.error = f"{type(exc).__name__}: {exc}"
            return peer

        if not peer.validated:
            # Retry without verification purely to fetch the presented cert.
            unverified_ctx = ssl.create_default_context()
            unverified_ctx.check_hostname = False
            unverified_ctx.verify_mode = ssl.CERT_NONE
            try:
                with socket.create_connection((host, port), timeout=self.config.connect_timeout) as sock:
                    with unverified_ctx.wrap_socket(sock, server_hostname=host) as tls:
                        pem = ssl.DER_cert_to_PEM_cert(tls.getpeercert(binary_form=True))
                        peer.available = True
            except (socket.timeout, OSError, ssl.SSLError) as exc:
                peer.error = peer.error or f"{type(exc).__name__}: {exc}"
                return peer

        info = decode_certificate(pem)
        peer.subject = info.get("subject", "")
        peer.issuer = info.get("issuer", "")
        peer.issuer_org = info.get("issuer_org", "")
        peer.not_after = info.get("not_after", "")
        peer.self_signed = bool(peer.issuer) and peer.issuer == peer.subject
        return peer

    # -- HTTP(S) -----------------------------------------------------------
    def http_get(
        self,
        url: str,
        allow_redirects: bool = False,
        timeout: Optional[float] = None,
    ) -> HttpResponse:
        response = HttpResponse(url=url)
        if requests is None:
            response.error = "requests-unavailable"
            return response
        try:
            resp = requests.get(
                url,
                allow_redirects=allow_redirects,
                timeout=timeout or self.config.http_timeout,
            )
        except Exception as exc:
            response.error = f"{type(exc).__name__}: {exc}"
            return response
        response.status = resp.status_code
        response.headers = {k.lower(): v for k, v in resp.headers.items()}
        response.body = resp.text[:4000]
        response.final_url = resp.url
        response.location = resp.headers.get("Location", "")
        response.ok = True
        return response

    # -- raw TCP -----------------------------------------------------------
    def tcp_open(self, host: str, port: int, timeout: Optional[float] = None) -> bool:
        try:
            with socket.create_connection((host, port), timeout=timeout or self.config.tcp_timeout):
                return True
        except OSError:
            return False


# ---------------------------------------------------------------------------
# Certificate decoding helpers (OpenSSL first, CPython fallback)
# ---------------------------------------------------------------------------
def _extract_org(dn: str) -> str:
    for part in dn.split(","):
        part = part.strip()
        if part.startswith("O =") or part.startswith("O="):
            return part.split("=", 1)[1].strip()
    return ""


def _parse_openssl_output(text: str) -> Dict[str, str]:
    info: Dict[str, str] = {}
    for line in text.splitlines():
        if line.startswith("issuer="):
            info["issuer"] = line[len("issuer="):].strip()
            info["issuer_org"] = _extract_org(info["issuer"])
        elif line.startswith("subject="):
            info["subject"] = line[len("subject="):].strip()
        elif line.startswith("notAfter="):
            info["not_after"] = line[len("notAfter="):].strip()
    return info


def _dn_to_str(rdns) -> str:
    parts = []
    for rdn in rdns or ():
        for key, value in rdn:
            parts.append(f"{key} = {value}")
    return ", ".join(parts)


def _dn_field(rdns, field_name: str) -> str:
    for rdn in rdns or ():
        for key, value in rdn:
            if key == field_name:
                return value
    return ""


def decode_certificate(pem: Optional[str]) -> Dict[str, str]:
    """Return issuer/subject/notAfter for a PEM certificate, {} on failure."""
    if not pem:
        return {}
    path: Optional[str] = None
    try:
        fd, path = tempfile.mkstemp(suffix=".pem")
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(pem)
        try:
            proc = subprocess.run(
                ["openssl", "x509", "-in", path, "-noout", "-issuer", "-subject", "-enddate"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if proc.returncode == 0 and proc.stdout.strip():
                return _parse_openssl_output(proc.stdout)
        except (OSError, subprocess.SubprocessError):
            pass
        try:  # CPython fallback
            decoded = ssl._ssl._test_decode_cert(path)  # type: ignore[attr-defined]
            return {
                "issuer": _dn_to_str(decoded.get("issuer")),
                "subject": _dn_to_str(decoded.get("subject")),
                "issuer_org": _dn_field(decoded.get("issuer"), "organizationName"),
                "not_after": decoded.get("notAfter", ""),
            }
        except Exception:
            return {}
    finally:
        if path and os.path.exists(path):
            try:
                os.unlink(path)
            except OSError:
                pass
