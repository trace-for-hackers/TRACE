"""Active/passive service, product and version enumerator.

Builds normalized ``tech.product.*`` and ``tech.service.*`` facts from a
small, bounded set of low-impact observations:

* HTTP response headers (Server, Via, X-Powered-By, WWW-Authenticate)
* HTML/meta generators and common asset fingerprints
* technology-specific response/body signatures
* TLS certificate metadata and negotiated protocol/cipher
* TCP reachability on a configurable list of common service ports
* a second HTTP probe on a few common application ports when reachable

The module is intentionally bounded: it does not perform port ranges,
credential attacks, directory brute force, or exploit traffic. Its job is
fingerprinting and feeding the NVD correlation layer.
"""
from __future__ import annotations

import os
import re
import socket
import ssl

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from urllib.parse import urljoin, urlsplit

from bs4 import BeautifulSoup

from knowledge.contracts import discovery_module, Produces
from knowledge.fact import fact
from knowledge.result import ModuleResult
from utils.requester import get


_VERSION_RE = r"(\d+(?:\.\d+){1,4}(?:[-+._~a-zA-Z0-9]+)?)"

# Ordered by specificity. The tuple is (vendor, normalized_product, version_regex).
_HEADER_PATTERNS = [
    ("microsoft", "internet_information_services", re.compile(r"\bMicrosoft-IIS/(\d+(?:\.\d+){1,3})", re.I)),
    ("apache", "apache", re.compile(r"\bApache/(\d+(?:\.\d+){1,3}(?:[a-zA-Z])?)", re.I)),
    ("nginx", "nginx", re.compile(r"\bnginx/(\d+(?:\.\d+){1,3})", re.I)),
    ("openssl", "openssl", re.compile(r"\bOpenSSL/(\d+(?:\.\d+){1,3}[a-zA-Z]?)", re.I)),
    ("php", "php", re.compile(r"\bPHP/(\d+(?:\.\d+){1,3})", re.I)),
    ("kong", "kong", re.compile(r"\b[Kk]ong/(\d+(?:\.\d+){1,3})", re.I)),
    ("caddy", "caddy", re.compile(r"\bCaddy/(\d+(?:\.\d+){1,3})", re.I)),
    ("litespeed", "litespeed", re.compile(r"\bLiteSpeed(?:/(\d+(?:\.\d+){1,3}))?", re.I)),
    ("gunicorn", "gunicorn", re.compile(r"\bgunicorn/(\d+(?:\.\d+){1,3})", re.I)),
]

_HEADER_NAMES = ("server", "via", "x-powered-by", "x-generator", "x-aspnet-version")

# Common bounded service probes. TRACE_SERVICE_PORTS can override this list.
_DEFAULT_PORTS = (80, 443, 3000, 3001, 5000, 8000, 8080, 8081, 8443, 8888)
_PORT_SERVICE_NAMES = {
    80: "http",
    443: "https",
    3000: "http",
    3001: "http",
    5000: "http",
    8000: "http",
    8080: "http",
    8081: "http",
    8443: "https",
    8888: "http",
}

# Generic server/body signatures. Versions are only emitted when the signature
# actually contains one. Product-only detections remain useful to downstream
# modules, but deliberately use lower confidence.
_RESPONSE_SIGNATURES = [
    ("palletsprojects", "flask", re.compile(r"\bWerkzeug/(\d+(?:\.\d+){1,3})\b", re.I)),
    ("palletsprojects", "flask", re.compile(r"werkzeug debugger", re.I)),
    ("nodejs", "node.js", re.compile(r"\bNode\.js\b", re.I)),
    ("expressjs", "express", re.compile(r"\bX-Powered-By:\s*Express\b", re.I)),
    ("tomcat", "tomcat", re.compile(r"\bApache Tomcat/(\d+(?:\.\d+){1,3})\b", re.I)),
    ("jetty", "jetty", re.compile(r"\bjetty/(\d+(?:\.\d+){1,3})\b", re.I)),
    ("uvicorn", "uvicorn", re.compile(r"\buvicorn\b", re.I)),
    ("django", "django", re.compile(r"csrfmiddlewaretoken|__debug__", re.I)),
    ("aspnet", "asp.net", re.compile(r"ASP\.NET|X-AspNet-Version|__VIEWSTATE", re.I)),
    ("php", "php", re.compile(r"PHP/" + _VERSION_RE, re.I)),
]

_JS_PATTERNS = {
    "jquery": re.compile(r"(?:jquery[.-])(\d+\.\d+\.\d+)", re.I),
    "lodash": re.compile(r"(?:lodash[.-])(\d+\.\d+\.\d+)", re.I),
    "bootstrap": re.compile(r"(?:bootstrap[.-])(\d+\.\d+\.\d+)", re.I),
    "angular": re.compile(r"(?:angular[.-])(\d+\.\d+\.\d+)", re.I),
    "react": re.compile(r"(?:react[.-])(\d+\.\d+\.\d+)", re.I),
    "vue": re.compile(r"(?:vue[.-])(\d+\.\d+\.\d+)", re.I),
}


def _parse_ports() -> tuple[int, ...]:
    raw = os.getenv("TRACE_SERVICE_PORTS", "")
    if not raw.strip():
        return _DEFAULT_PORTS
    ports = []
    for token in raw.split(","):
        try:
            port = int(token.strip())
        except ValueError:
            continue
        if 1 <= port <= 65535:
            ports.append(port)
    return tuple(dict.fromkeys(ports)) or _DEFAULT_PORTS


def _version_from_text(pattern: re.Pattern[str], value: str) -> str | None:
    match = pattern.search(value or "")
    if not match:
        return None
    return match.group(1) if match.lastindex else None


def _tcp_probe(host: str, port: int, timeout: float = 0.8) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (OSError, ValueError):
        return False


def _tls_probe(host: str, port: int, timeout: float = 2.0) -> dict | None:
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with context.wrap_socket(raw, server_hostname=host) as tls:
                der = tls.getpeercert(binary_form=True)
                cert_info = {}
                if der:
                    try:
                        cert = x509.load_der_x509_certificate(der, default_backend())
                        cert_info = {
                            "subject": cert.subject.rfc4514_string(),
                            "issuer": cert.issuer.rfc4514_string(),
                            "serial": format(cert.serial_number, "x"),
                            "not_before": cert.not_valid_before_utc.isoformat(),
                            "not_after": cert.not_valid_after_utc.isoformat(),
                            "san_dns": [
                                str(name) for name in cert.extensions
                                .get_extension_for_class(x509.SubjectAlternativeName)
                                .value.get_values_for_type(x509.DNSName)
                            ] if any(isinstance(ext.value, x509.SubjectAlternativeName) for ext in cert.extensions) else [],
                        }
                    except Exception:
                        cert_info = {}
                return {
                    "protocol": tls.version(),
                    "cipher": tls.cipher()[0] if tls.cipher() else None,
                    **cert_info,
                }
    except (OSError, ssl.SSLError, ValueError):
        return None


def _http_url_for_port(base_target: str, port: int) -> str:
    parsed = urlsplit(base_target)
    scheme = "https" if port in {443, 8443} else "http"
    host = parsed.hostname or ""
    host_fmt = f"[{host}]" if ":" in host and not host.startswith("[") else host
    if (scheme == parsed.scheme and port == parsed.port) or (port == 80 and scheme == "http") or (port == 443 and scheme == "https"):
        return base_target
    return f"{scheme}://{host_fmt}:{port}/"



@discovery_module(
    requires=[],
    produces=[Produces("tech.product.*", durable=False), Produces("tech.service.*", durable=False)],
    cost=4,
    category="service_enumeration",
    display_name="Enumeração de Serviços e Versões",
    summary=(
        "Correlaciona headers HTTP, HTML/meta, fingerprints de assets, assinaturas de resposta, "
        "TLS e uma lista limitada de portas comuns para produzir produtos, serviços e versões normalizados."
    ),
)
class ServiceVersionEnumerator:
    name = "service_version_enumerator"

    def run(self, target: str):
        primary = get(target)
        if primary is None:
            return None

        parsed = urlsplit(target)
        host = parsed.hostname
        if not host:
            return None

        product_evidence = {}
        service_evidence = {}

        def emit_product(vendor, product, version, confidence, source, evidence):
            key = f"tech.product.{product}"
            entry = product_evidence.setdefault(key, {
                "vendor": vendor,
                "product": product,
                "version": version,
                "sources": [],
                "evidence": [],
                "confidence": 0.0,
            })
            if version and not entry.get("version"):
                entry["version"] = version
            if source not in entry["sources"]:
                entry["sources"].append(source)
            if evidence and evidence not in entry["evidence"]:
                entry["evidence"].append(evidence)
            entry["confidence"] = max(entry["confidence"], confidence)

        def emit_service(name, port=None, protocol=None, confidence=0.7, source="tcp", evidence=None):
            key = f"tech.service.{name}"
            entry = service_evidence.setdefault(key, {
                "service": name,
                "port": port,
                "protocol": protocol,
                "sources": [],
                "evidence": [],
                "confidence": 0.0,
            })
            if source not in entry["sources"]:
                entry["sources"].append(source)
            if evidence and evidence not in entry["evidence"]:
                entry["evidence"].append(evidence)
            entry["confidence"] = max(entry["confidence"], confidence)

        # ------------------------------------------------------------------
        # 1) Primary HTTP headers
        # ------------------------------------------------------------------
        headers = {str(k).lower(): str(v) for k, v in primary.headers.items()}
        for header_name in _HEADER_NAMES:
            value = headers.get(header_name, "")
            if not value:
                continue
            for vendor, product, pattern in _HEADER_PATTERNS:
                version = _version_from_text(pattern, value)
                if version:
                    emit_product(vendor, product, version, 0.98, f"http.{header_name}", value)
                    emit_service(product, parsed.port or (443 if parsed.scheme == "https" else 80), parsed.scheme, 0.98, f"http.{header_name}", value)

            # Product-only / framework headers where a version isn't present.
            lower = value.lower()
            if "express" in lower and "x-powered-by" == header_name:
                emit_product("expressjs", "express", None, 0.95, "http.x-powered-by", value)
                emit_service("express", parsed.port, parsed.scheme, 0.95, "http.x-powered-by", value)
            if "next.js" in lower:
                emit_product("vercel", "next.js", None, 0.93, f"http.{header_name}", value)
            if "cloudflare" in lower:
                emit_product("cloudflare", "cloudflare", None, 0.92, f"http.{header_name}", value)
                emit_service("cdn", parsed.port, parsed.scheme, 0.92, f"http.{header_name}", value)

        emit_service("http" if parsed.scheme == "http" else "https", parsed.port or (443 if parsed.scheme == "https" else 80), parsed.scheme, 0.99, "primary_http", str(primary.status_code))

        # ------------------------------------------------------------------
        # 2) HTML/meta and asset fingerprints
        # ------------------------------------------------------------------
        body = primary.text or ""
        soup = BeautifulSoup(body, "html.parser")

        generator = soup.find("meta", attrs={"name": re.compile("^generator$", re.I)})
        if generator and generator.get("content"):
            content = str(generator.get("content"))
            wp = re.search(r"wordpress\s+([0-9]+(?:\.[0-9]+){1,2})", content, re.I)
            if wp:
                emit_product("wordpress", "wordpress", wp.group(1), 1.0, "meta.generator", content)
                emit_service("wordpress", parsed.port, parsed.scheme, 1.0, "meta.generator", content)
            else:
                # Preserve a product-only framework fingerprint when useful.
                for vendor, product in (("joomla", "joomla"), ("drupal", "drupal"), ("magento", "magento")):
                    if vendor in content.lower():
                        emit_product(vendor, product, None, 0.94, "meta.generator", content)
                        emit_service(product, parsed.port, parsed.scheme, 0.94, "meta.generator", content)

        # Framework fingerprints that commonly omit a versioned asset name.
        ng_version = soup.find(attrs={"ng-version": True})
        if ng_version and ng_version.get("ng-version"):
            version = str(ng_version.get("ng-version"))
            emit_product("angular", "angular", version, 0.99, "html.ng-version", version)
            emit_service("angular", parsed.port, parsed.scheme, 0.97, "html.ng-version", version)

        if soup.find(id=re.compile(r"__next$|__next-build", re.I)) or re.search(r"(?:_next/static|__NEXT_DATA__)", body, re.I):
            emit_product("vercel", "next.js", None, 0.88, "html.nextjs", "Next.js signature")
            emit_service("next.js", parsed.port, parsed.scheme, 0.88, "html.nextjs", "Next.js signature")

        if soup.find(id="app") and re.search(r"data-v-[0-9a-f]+|Vue", body, re.I):
            emit_product("vuejs", "vue", None, 0.78, "html.vue", "Vue.js signature")
            emit_service("vue", parsed.port, parsed.scheme, 0.78, "html.vue", "Vue.js signature")

        for tag in soup.find_all(["script", "link"], src=True):
            asset_url = urljoin(target, str(tag.get("src", "")))
            for library, pattern in _JS_PATTERNS.items():
                match = pattern.search(asset_url)
                if match:
                    emit_product(library, library, match.group(1), 0.93, "asset.url", asset_url)
                    emit_service(library, parsed.port, parsed.scheme, 0.90, "asset.url", asset_url)
        for tag in soup.find_all("link", href=True):
            asset_url = urljoin(target, str(tag.get("href", "")))
            for library, pattern in _JS_PATTERNS.items():
                match = pattern.search(asset_url)
                if match:
                    emit_product(library, library, match.group(1), 0.90, "asset.url", asset_url)
                    emit_service(library, parsed.port, parsed.scheme, 0.88, "asset.url", asset_url)

        # ------------------------------------------------------------------
        # 3) Response-specific signatures
        # ------------------------------------------------------------------
        signature_blob = "\n".join([
            body[:250_000],
            *(f"{k}: {v}" for k, v in headers.items()),
        ])
        for vendor, product, pattern in _RESPONSE_SIGNATURES:
            match = pattern.search(signature_blob)
            if not match:
                continue
            version = match.group(1) if match.lastindex else None
            confidence = 0.91 if version else 0.82
            evidence = match.group(0)[:500]
            emit_product(vendor, product, version, confidence, "response.signature", evidence)
            emit_service(product, parsed.port, parsed.scheme, confidence, "response.signature", evidence)

        # Known application responses can identify products even when the
        # framework suppresses Server/X-Powered-By.
        lowered_body = body[:250_000].lower()
        if "juice shop" in lowered_body or "bkimminich" in lowered_body:
            emit_product("owasp", "juice_shop", None, 0.95, "response.body", "OWASP Juice Shop signature")
            emit_service("juice_shop", parsed.port, parsed.scheme, 0.95, "response.body", "OWASP Juice Shop signature")

        # ------------------------------------------------------------------
        # 4) Bounded TCP service discovery + targeted HTTP observations
        # ------------------------------------------------------------------
        reachable_ports = []
        for port in _parse_ports():
            if _tcp_probe(host, port):
                reachable_ports.append(port)
                protocol = _PORT_SERVICE_NAMES.get(port, "tcp")
                emit_service(protocol, port, "tls" if port in {443, 8443} else "tcp", 0.76, "tcp.connect", f"{host}:{port}")

                if port in {443, 8443}:
                    tls_info = _tls_probe(host, port)
                    if tls_info:
                        emit_service("tls", port, "tls", 0.96, "tls.handshake", tls_info)
                        cert_names = []
                        subject = tls_info.get("subject")
                        issuer = tls_info.get("issuer")
                        if subject:
                            cert_names.append(subject)
                        if issuer:
                            cert_names.append(issuer)
                        cert_names.extend(tls_info.get("san_dns", []))
                        if cert_names:
                            emit_service("tls_certificate", port, "tls", 0.93, "tls.certificate", cert_names[:20])

        # Probe a small set of reachable HTTP ports so an app that does not
        # expose identifying headers on the primary URL can still be found.
        seen_probe_ports = set()
        for port in reachable_ports:
            if _PORT_SERVICE_NAMES.get(port) != "http" or port == parsed.port:
                continue
            if port in seen_probe_ports:
                continue
            seen_probe_ports.add(port)
            probe_url = _http_url_for_port(target, port)
            probe = get(probe_url)
            if probe is None:
                continue
            probe_headers = {str(k).lower(): str(v) for k, v in probe.headers.items()}
            probe_body = probe.text or ""
            for header_name in _HEADER_NAMES:
                value = probe_headers.get(header_name, "")
                if not value:
                    continue
                for vendor, product, pattern in _HEADER_PATTERNS:
                    version = _version_from_text(pattern, value)
                    if version:
                        emit_product(vendor, product, version, 0.96, f"port.{port}.http.{header_name}", value)
                        emit_service(product, port, "http", 0.96, f"port.{port}.http.{header_name}", value)
            probe_blob = "\n".join([probe_body[:150_000], *(f"{k}: {v}" for k, v in probe_headers.items())])
            for vendor, product, pattern in _RESPONSE_SIGNATURES:
                match = pattern.search(probe_blob)
                if match:
                    version = match.group(1) if match.lastindex else None
                    emit_product(vendor, product, version, 0.88 if version else 0.80, f"port.{port}.response", match.group(0)[:500])
                    emit_service(product, port, "http", 0.88 if version else 0.80, f"port.{port}.response", match.group(0)[:500])

        # ------------------------------------------------------------------
        # 5) Materialize facts. One fact per normalized product/service key,
        # aggregating all observations so the KnowledgeStore does not lose
        # multiple corroborating signals for the same product.
        # ------------------------------------------------------------------
        result_facts = []
        for key, item in sorted(product_evidence.items()):
            result_facts.append(fact(
                key=key,
                value={
                    "vendor": item["vendor"],
                    "product": item["product"],
                    "version": item["version"],
                    "sources": item["sources"],
                    "evidence": item["evidence"][:12],
                },
                confidence=item["confidence"],
                produced_by=self.name,
                target=target,
            ))

        for key, item in sorted(service_evidence.items()):
            result_facts.append(fact(
                key=key,
                value={
                    "service": item["service"],
                    "port": item["port"],
                    "protocol": item["protocol"],
                    "sources": item["sources"],
                    "evidence": item["evidence"][:12],
                },
                confidence=item["confidence"],
                produced_by=self.name,
                target=target,
            ))

        if not result_facts:
            return None
        return ModuleResult(findings=[], facts=result_facts)
