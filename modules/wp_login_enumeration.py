from utils.requester import post # Assumindo que você tenha um método post
from core.finding import Finding
from knowledge.contracts import discovery_module, Requirement

@discovery_module(
    requires=[Requirement("cms.wordpress.detected", min_confidence=0.5)],
    cost=1,
    display_name="Enumeração de Usuário via Recuperação de Senha",
    summary="Testa o formulário de recuperação de senha (wp-login.php?action=lostpassword) com um usuário inexistente, comparando a resposta para detectar diferenças que confirmem usuários válidos.",
)
class WPEnumerationLogin:
    name = "wp_login_enumeration"

    def run(self, target):
        url = f"{target}/wp-login.php?action=lostpassword"
        # Tentamos um usuário que provavelmente não existe
        payload = {'user_login': 'non_existent_user_9988'}
        r = post(url, data=payload)

        # O WordPress costuma mudar a mensagem de erro se o usuário existe ou não
        # Erro comum: "Invalid username or email" vs "Link has been sent"
        if r and ("Invalid" in r.text or "not found" in r.text):
            f = Finding(
                module=self.name,
                title="User Enumeration via Forgot Password",
                severity="low",
                description="The login page reveals if a username/email exists based on the error message.",
                endpoint="/wp-login.php?action=lostpassword",
                evidence="Error message differentiation detected"
            )
            f.business_impact = "Attackers can build a list of valid usernames to perform targeted brute-force or phishing attacks."
            f.remediation = "Use a generic error message for both successful and failed password reset requests."
            f.exploitability = "Easy"

            return [f.to_dict()]
        return None