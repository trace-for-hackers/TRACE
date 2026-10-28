"""
modules/tls_weakness_scanner.py

Checa cifra fraca e problema de certificado (autoassinado, expirado,
emissor não confiável) -- NÃO checa HSTS, isso já é coberto por
security_headers_baseline.py (categoria diferente, evita duplicar).

TÉCNICA: tenta handshake TLS NORMAL (validando o certificado, como um
navegador faria). Se falhar com SSLCertVerificationError, a MENSAGEM de
erro do OpenSSL já classifica o motivo (autoassinado, expirado, emissor
desconhecido) -- não precisa parsear certificado manualmente com
biblioteca extra. Depois, faz uma SEGUNDA tentativa sem validar (só pra
capturar qual protocolo/cifra o servidor negociou), independente do
certificado ter sido aceito ou não -- servidor com certificado ruim MAS
cifra forte é um problema diferente de cifra fraca, os dois são
reportados separadamente.
"""

from __future__ import annotations

import socket
import ssl
from urllib.parse import urlparse

from knowledge.contracts import discovery_module, Produces
from knowledge.result import ModuleResult

_WEAK_PROTOCOLS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}

# substring em nome de cifra (formato OpenSSL, ex. "ECDHE-RSA-RC4-SHA")
# que indica fraqueza conhecida -- RC4/DES/3DES quebrados, NULL sem
# criptografia nenhuma, EXPORT deliberadamente enfraquecida (era pra
# atender restrição de exportação dos anos 90), ADH/AECDH sem
# autenticação (Diffie-Hellman anônimo -- "ANON" sozinho não bate, o
# nome real no OpenSSL é "ADH"/"AECDH", achado testando).
_WEAK_CIPHER_KEYWORDS = ("RC4", "DES", "3DES", "NULL", "EXPORT", "MD5", "ADH", "AECDH")


def is_weak_protocol(protocol_name: str | None) -> bool:
    return protocol_name in _WEAK_PROTOCOLS


def is_weak_cipher(cipher_name: str | None) -> bool:
    if not cipher_name:
        return False
    upper = cipher_name.upper()
    return any(kw in upper for kw in _WEAK_CIPHER_KEYWORDS)


def classify_cert_error(error_message: str) -> str:
    """Classifica a mensagem de erro do OpenSSL num motivo legível --
    string de erro varia por versão do OpenSSL, então casa por
    substring, não por código de erro exato."""
    msg = error_message.lower()
    if "self signed" in msg or "self-signed" in msg:
        return "self_signed"
    if "certificate has expired" in msg or "expired" in msg:
        return "expired"
    if "hostname mismatch" in msg or "doesn't match" in msg or "does not match" in msg:
        return "hostname_mismatch"
    if "unable to get local issuer" in msg or "unable to get issuer" in msg:
        return "untrusted_issuer"
    return "unknown_certificate_error"


_CERT_ERROR_DESCRIPTIONS = {
    "self_signed": ("critical", "O certificado é autoassinado -- não há autoridade certificadora confiável validando a identidade do servidor, abrindo espaço pra ataque man-in-the-middle sem o usuário perceber (nenhum aviso visível se o cliente não checar corretamente)."),
    "expired": ("high", "O certificado TLS está expirado -- clientes que respeitam a validade vão rejeitar a conexão ou (pior) o usuário aprende a clicar 'continuar mesmo assim', hábito perigoso que facilita phishing."),
    "hostname_mismatch": ("high", "O certificado não corresponde ao hostname do alvo -- sinal de configuração errada ou de certificado reaproveitado de outro domínio."),
    "untrusted_issuer": ("medium", "O certificado foi emitido por uma autoridade não reconhecida pela cadeia de confiança padrão -- pode ser CA interna legítima (ambiente corporativo) ou sinal de problema, precisa checar caso a caso."),
    "unknown_certificate_error": ("medium", "Erro de validação de certificado não classificado nas categorias conhecidas -- ver evidência para a mensagem original do OpenSSL."),
}


@discovery_module(
    requires=(),
    produces=[],
    cost=2,
    category="cryptographic_failures",
    display_name="Scanner de Fraqueza TLS",
    summary="Handshake TLS real contra o alvo -- classifica erro de certificado (autoassinado, expirado, emissor não confiável) pela mensagem do OpenSSL, e verifica se protocolo/cifra negociados são conhecidos por fraqueza.",
)
class TLSWeaknessScanner:
    name = "tls_weakness_scanner"

    def run(self, target: str):
        if not target.startswith("https://"):
            return None  # nada de TLS pra inspecionar num alvo HTTP puro

        parsed = urlparse(target)
        hostname = parsed.hostname
        port = parsed.port or 443
        if not hostname:
            return None

        findings = []
        cert_error_kind = None
        cert_error_raw = None
        protocol = None
        cipher_name = None

        try:
            context = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=8) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cipher_name, protocol, _bits = ssock.cipher()
        except ssl.SSLCertVerificationError as e:
            cert_error_raw = str(e)
            cert_error_kind = classify_cert_error(cert_error_raw)
            # segunda tentativa, sem validar -- só pra saber protocolo/cifra
            # negociados mesmo com certificado ruim (são problemas separados)
            try:
                unverified = ssl._create_unverified_context()
                with socket.create_connection((hostname, port), timeout=8) as sock:
                    with unverified.wrap_socket(sock, server_hostname=hostname) as ssock:
                        cipher_name, protocol, _bits = ssock.cipher()
            except Exception:
                pass  # se nem isso funcionar, reporta só o problema de certificado
        except (socket.timeout, ConnectionRefusedError, socket.gaierror) as e:
            print(f"[tls_weakness_scanner] não conseguiu conectar em {hostname}:{port}: {e}")
            return None
        except Exception as e:
            print(f"[tls_weakness_scanner] erro inesperado: {type(e).__name__}: {e}")
            return None

        if cert_error_kind:
            severity, description = _CERT_ERROR_DESCRIPTIONS[cert_error_kind]
            findings.append({
                "title": f"Certificado TLS inválido: {cert_error_kind.replace('_', ' ')}",
                "severity": severity,
                "module": self.name,
                "category": "cryptographic_failures",
                "endpoint": target,
                "description": description,
                "business_impact": description,
                "remediation": "Emitir/renovar certificado válido através de uma autoridade certificadora confiável (ex.: Let's Encrypt para uso gratuito).",
                "evidence": {"error_kind": cert_error_kind, "raw_error": cert_error_raw},
            })

        if is_weak_protocol(protocol):
            findings.append({
                "title": f"Protocolo TLS obsoleto negociado: {protocol}",
                "severity": "high",
                "module": self.name,
                "category": "cryptographic_failures",
                "endpoint": target,
                "description": f"O servidor aceitou negociar {protocol}, protocolo com vulnerabilidade conhecida e sem suporte de segurança ativo.",
                "business_impact": "Protocolo obsoleto pode ser forçado por ataque de downgrade, expondo a conexão a técnicas de quebra conhecidas.",
                "remediation": "Desabilitar suporte a SSLv2/SSLv3/TLSv1.0/TLSv1.1 no servidor, aceitar apenas TLSv1.2+.",
                "evidence": {"negotiated_protocol": protocol},
            })

        if is_weak_cipher(cipher_name):
            findings.append({
                "title": f"Cifra TLS fraca negociada: {cipher_name}",
                "severity": "high",
                "module": self.name,
                "category": "cryptographic_failures",
                "endpoint": target,
                "description": f"O servidor aceitou negociar a cifra '{cipher_name}', com fraqueza criptográfica conhecida.",
                "business_impact": "Cifra fraca pode permitir decifrar o tráfego capturado, mesmo que a conexão pareça criptografada.",
                "remediation": "Remover cifras fracas (RC4, DES, 3DES, NULL, EXPORT, MD5, anônimas) da lista de cifras aceitas pelo servidor.",
                "evidence": {"negotiated_cipher": cipher_name},
            })

        if not findings:
            return None
        return ModuleResult(findings=findings)
