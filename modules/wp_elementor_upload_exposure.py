from utils.requester import get
from core.finding import Finding
from knowledge.contracts import discovery_module, Requirement


@discovery_module(
    requires=[Requirement("cms.wordpress.detected", min_confidence=0.5),
              Requirement("tech.elementor.present", min_confidence=0.5)],
    cost=1,
    category="elementor",
    display_name="Elementor Vulnerável a Upload Autenticado (CVE-2023-48777)",
    summary="Verifica a versão do Elementor contra CVE-2023-48777 e se o registro público de usuários está aberto, condição que viabiliza a exploração por um atacante sem credenciais prévias.",
)
class WPElementorUploadExposure:
    """
    Verifica condições de exposição relacionadas a CVE-2023-48777
    (Elementor < 3.18.2 -- upload arbitrário de arquivo via importação de
    template, autenticado, papel Contributor ou superior).

    IMPORTANTE -- o que este módulo confirma e o que NÃO confirma:

    CVE-2023-48777 exige autenticação (Contributor+) para ser explorado --
    não é um RCE não-autenticado. Um scanner anônimo, sem credenciais
    válidas, não pode confirmar exploração real deste CVE. O que ESTE
    módulo pode legitimamente verificar, de forma não-autenticada, são as
    DUAS pré-condições que tornam o site um alvo viável caso um atacante
    já tenha (ou consiga, via outro vetor) uma conta de baixo privilégio:

        1. A versão do Elementor está na faixa vulnerável (cruzamento de
           versão, mesma lógica do wp_known_vulnerable_assets.py, mas
           focado especificamente neste CVE).
        2. O registro público de novos usuários está habilitado
           (wp-login.php?action=register responde com o formulário) --
           que é o vetor mais comum de um atacante OBTER uma conta
           Contributor+ sem precisar de credenciais roubadas.

    Se as duas condições baterem, o achado é reportado como "exposição
    confirmada, exploração requer autenticação" -- não como RCE confirmado.
    Isso evita o falso senso de urgência de reportar um RCE não-autenticado
    que, tecnicamente, não existe para este CVE específico.

    Diferente de wp_known_vulnerable_assets.py (cruzamento genérico contra
    uma lista de CVEs, qualquer plugin), este módulo é dedicado a um único
    CVE de alto impacto no Elementor, com a verificação extra do vetor de
    registro de usuário -- contexto que o matcher genérico não tem.
    """
    name = "wp_elementor_upload_exposure"

    VULNERABLE_MAX_VERSION = (3, 18, 1)  # corrigido na 3.18.2

    def run(self, target):
        version_info = self._detect_elementor_version(target)
        registration_open = self._check_public_registration(target)

        if version_info is None:
            return None

        version_str, is_vulnerable_version = version_info

        if not is_vulnerable_version:
            return None

        f = Finding(
            module=self.name,
            title="Elementor Vulnerable to CVE-2023-48777 (Authenticated Upload to RCE)",
            severity="high" if registration_open else "medium",
            description=(
                "The detected Elementor version is within the range affected by "
                "CVE-2023-48777, an authenticated arbitrary file upload vulnerability "
                "exploitable by Contributor-level users and above via template import."
            ),
            endpoint="/wp-content/plugins/elementor/",
            evidence={
                "detected_version": version_str,
                "vulnerable_max_version": "3.18.1",
                "cve": "CVE-2023-48777",
                "public_user_registration_open": registration_open,
            },
        )

        if registration_open:
            f.business_impact = (
                "Public user registration is open AND the vulnerable Elementor version "
                "is present. An attacker can self-register a low-privilege account and "
                "then exploit CVE-2023-48777 to upload arbitrary PHP files, achieving "
                "remote code execution without needing any stolen credentials."
            )
        else:
            f.business_impact = (
                "The vulnerable Elementor version is present, but public registration "
                "appears closed. Exploitation of CVE-2023-48777 still requires an "
                "attacker to obtain Contributor-level credentials through another "
                "vector (credential stuffing, phishing, or an existing low-privilege "
                "account)."
            )

        f.remediation = (
            "Update Elementor to version 3.18.2 or later immediately. Additionally, "
            "disable public user registration if it is not required, and review "
            "existing Contributor-level accounts for legitimacy."
        )

        f.exploitability = "Easy" if registration_open else "Moderate"

        return [f.to_dict()]

    def _detect_elementor_version(self, target):
        """Tenta extrair a versão do Elementor via readme.txt do plugin (sinal
        mais confiável e barato). Retorna (version_str, is_vulnerable) ou None
        se a versão não puder ser determinada."""
        r = get(f"{target}/wp-content/plugins/elementor/readme.txt")
        if not r or r.status_code != 200:
            return None

        import re
        match = re.search(r"Stable tag:\s*([\d.]+)", r.text)
        if not match:
            return None

        version_str = match.group(1)
        try:
            version_tuple = tuple(int(p) for p in version_str.split("."))
        except ValueError:
            return None

        is_vulnerable = version_tuple <= self.VULNERABLE_MAX_VERSION
        return version_str, is_vulnerable

    def _check_public_registration(self, target) -> bool:
        r = get(f"{target}/wp-login.php?action=register")
        if not r or r.status_code != 200:
            return False
        body = (r.text or "").lower()
        return 'id="registerform"' in body or "user_login" in body and "register" in body