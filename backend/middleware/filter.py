import re
import html


class Filter:
    

    def clean(self, prompt: str) -> str:
        # Décodage HTML (évite les encodages d'injection)
        prompt = html.unescape(prompt)

        # Suppression des balises HTML/XML
        prompt = re.sub(r"<[^>]+>", "", prompt)

        # Suppression des séquences d'échappement ANSI
        prompt = re.sub(r"\x1b\[[0-9;]*m", "", prompt)

        # Suppression des caractères de contrôle (sauf newline/tab)
        prompt = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", prompt)

        # Normalisation des espaces multiples
        prompt = re.sub(r"[ \t]{2,}", " ", prompt)

        # Suppression des lignes vides excessives (max 2 newlines consécutifs)
        prompt = re.sub(r"\n{3,}", "\n\n", prompt)

        return prompt.strip()
