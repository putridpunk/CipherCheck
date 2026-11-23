"""Plain-language (Portuguese) presentation of an Analysis, for the GUI.

No jargon: no "entropy", "bits", "hash" or "dictionary" shown to the user.
"""

from __future__ import annotations

import secrets
import string
from dataclasses import dataclass, field

from .analyzer import Analysis
from .entropy import OFFLINE_GUESSES_PER_SEC

VERDICTS = {
    "VERY WEAK": ("MUITO FRACA", "#ff3b3b", 1),
    "WEAK": ("FRACA", "#ff8c1a", 2),
    "MODERATE": ("RAZOÁVEL", "#f2e600", 3),
    "STRONG": ("FORTE", "#00ff41", 4),
    "VERY STRONG": ("MUITO FORTE", "#7dffb0", 5),
}

HEADLINES = {
    "VERY WEAK": "Um hacker entrava nesta conta quase de imediato.",
    "WEAK": "Dá algum trabalho a um hacker, mas não muito.",
    "MODERATE": "Aguenta ataques simples, mas dá para melhorar.",
    "STRONG": "Boa senha! Vai ser difícil de descobrir.",
    "VERY STRONG": "Excelente! Praticamente impossível de adivinhar.",
}

PROBLEMS = {
    "common_password": "É uma das senhas mais usadas do mundo. Os hackers testam estas primeiro.",
    "word": "Tem palavras normais, que são fáceis de adivinhar.",
    "sequence": "Tem sequências previsíveis (como 123 ou abc).",
    "repeat_char": "Repete o mesmo carácter várias vezes (como aaa ou 111).",
    "repeat_block": "Repete o mesmo pedaço várias vezes (como abcabc).",
    "keyboard": "Segue as teclas do teclado em linha (como qwerty ou asdf).",
    "year": "Tem um ano (como 1998 ou 2024), o que é fácil de adivinhar.",
}
TIPS = {
    "common_password": "Escolhe algo que nunca viste numa lista de senhas populares.",
    "word": "Evita palavras do dia a dia, nomes e coisas que se encontram numa pesquisa.",
    "sequence": "Foge de sequências como 123 ou abc.",
    "repeat_char": "Não repitas o mesmo carácter.",
    "repeat_block": "Não repitas pedaços da senha.",
    "keyboard": "Foge de padrões do teclado, como qwerty.",
    "year": "Não uses datas de nascimento nem anos.",
}


@dataclass
class FriendlyReport:
    verdict: str
    color: str
    level: int  # 1..5, for the strength bar
    headline: str
    crack_time: str
    bad: list[str] = field(default_factory=list)
    good: list[str] = field(default_factory=list)
    tips: list[str] = field(default_factory=list)


def duration_pt(seconds: float) -> str:
    if seconds < 1:
        return "menos de 1 segundo"
    years = seconds / 31_557_600
    if years >= 1_000_000_000:
        return "mais de mil milhões de anos"
    if years >= 1_000_000:
        return f"cerca de {int(years // 1_000_000)} milhões de anos"
    for name, plural, size in (("ano", "anos", 31_557_600), ("dia", "dias", 86_400),
                               ("hora", "horas", 3_600), ("minuto", "minutos", 60),
                               ("segundo", "segundos", 1)):
        if seconds >= size:
            n = int(seconds // size)
            return f"cerca de {n:,} {name if n == 1 else plural}".replace(",", " ")
    return "menos de 1 segundo"


def explain(a: Analysis) -> FriendlyReport:
    verdict, color, level = VERDICTS[a.label]
    seconds = 2 ** max(a.estimated_bits - 1, 0) / OFFLINE_GUESSES_PER_SEC
    kinds = {m.kind for m in a.matches}

    bad: list[str] = []
    tips: list[str] = []
    if a.length < 8:
        bad.append("É demasiado curta.")
        tips.append("Usa pelo menos 12 carácteres. O tamanho é o que mais ajuda.")
    elif a.length < 12:
        bad.append("Podia ser mais comprida (o ideal são 12 ou mais carácteres).")
    for kind in ("common_password", "word", "sequence", "repeat_char",
                 "repeat_block", "keyboard", "year"):
        if kind in kinds:
            bad.append(PROBLEMS[kind])
            tips.append(TIPS[kind])
    if any(m.leet for m in a.matches if m.kind in ("word", "common_password")):
        bad.append("Trocar letras por símbolos (a por @, o por 0) não engana ninguém: os hackers já testam isso.")
        tips.append("Em vez de trocar letras, junta várias palavras sem relação entre si.")
    if a.word_plus_digits:
        bad.append("Uma palavra com uns números no fim é um truque muito comum.")

    good: list[str] = []
    if a.length >= 12:
        good.append(f"Bom tamanho: {a.length} carácteres.")
    if a.length and "common_password" not in kinds:
        good.append("Não é uma das senhas mais populares.")
    if a.passphrase_words:
        good.append(f"Parece uma frase de {a.passphrase_words} palavras. Boa ideia!")
        if a.label in ("VERY WEAK", "WEAK", "MODERATE"):
            tips.append("Junta mais palavras aleatórias à frase (4 ou 5 é o ideal).")
    if not bad and a.length:
        good.append("Não encontrámos padrões previsíveis.")

    if a.label in ("VERY WEAK", "WEAK", "MODERATE"):
        tips.append("Usa o botão GERAR para criar uma senha forte e guarda-a num gestor de senhas.")
    tips.append("Usa uma senha diferente em cada conta.")

    return FriendlyReport(verdict, color, level, HEADLINES[a.label], duration_pt(seconds),
                          bad, good, list(dict.fromkeys(tips)))


def generate_password(length: int = 16) -> str:
    """Random password with letters, digits and symbols (always one of each)."""
    sets = [string.ascii_lowercase, string.ascii_uppercase, string.digits, "!@#$%&*?-_=+"]
    pool = "".join(sets)
    chars = [secrets.choice(s) for s in sets]
    chars += [secrets.choice(pool) for _ in range(length - len(chars))]
    secrets.SystemRandom().shuffle(chars)
    return "".join(chars)
