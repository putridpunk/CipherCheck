"""Português (Portugal)."""

NAME = "Português"
RTL = False


def plural(n: int) -> int:
    return 0 if n == 1 else 1


UNITS = [("ano", "anos"), ("dia", "dias"), ("hora", "horas"),
         ("minuto", "minutos"), ("segundo", "segundos")]

STRINGS = {
    "subtitle": "> descobre se a tua senha aguenta um hacker",
    "prompt": "root@tu:~$ escreve a tua senha",
    "show": "mostrar", "hide": "esconder",
    "privacy": "Fica tudo no teu computador. Nada é enviado nem guardado.",
    "gen": "GERAR SENHA FORTE", "copy": "COPIAR", "clear": "LIMPAR",
    "idle_headline": "Escreve uma senha em cima para começar.",
    "idle_1": "A análise aparece aqui enquanto escreves.",
    "idle_2": "Dica: não precisas de usar a tua senha verdadeira. Experimenta uma parecida para ver como funciona.",
    "crack": "Um hacker com um computador potente descobria-a em: {time}",
    "hdr_bad": "[ O QUE ESTÁ MAL ]", "hdr_good": "[ O QUE ESTÁ BEM ]", "hdr_tips": "[ COMO MELHORAR ]",
    "st_generated": "Senha criada! Copia-a e guarda-a num sítio seguro.",
    "st_copied": "Copiado! Vai ser apagado da área de transferência em 30 segundos.",
    "st_empty": "Ainda não escreveste nenhuma senha.",
    "st_similar": "Criámos uma versão forte da tua senha! Copia-a e guarda-a num sítio seguro.",
    "st_already": "A tua senha já é forte. Mantivemo-la como está.",
    "v1": "MUITO FRACA", "v2": "FRACA", "v3": "RAZOÁVEL", "v4": "FORTE", "v5": "MUITO FORTE",
    "h1": "Um hacker entrava nesta conta quase de imediato.",
    "h2": "Dá algum trabalho a um hacker, mas não muito.",
    "h3": "Aguenta ataques simples, mas dá para melhorar.",
    "h4": "Boa senha! Vai ser difícil de descobrir.",
    "h5": "Excelente! Praticamente impossível de adivinhar.",
    "p_common": "É uma das senhas mais usadas do mundo. Os hackers testam estas primeiro.",
    "p_word": "Tem palavras normais, que são fáceis de adivinhar.",
    "p_sequence": "Tem sequências previsíveis (como 123 ou abc).",
    "p_repeat_char": "Repete o mesmo carácter várias vezes (como aaa ou 111).",
    "p_repeat_block": "Repete o mesmo pedaço várias vezes (como abcabc).",
    "p_keyboard": "Segue as teclas do teclado em linha (como qwerty ou asdf).",
    "p_year": "Tem um ano (como 1998 ou 2024), o que é fácil de adivinhar.",
    "t_common": "Escolhe algo que nunca viste numa lista de senhas populares.",
    "t_word": "Evita palavras do dia a dia, nomes e coisas que se encontram numa pesquisa.",
    "t_sequence": "Foge de sequências como 123 ou abc.",
    "t_repeat_char": "Não repitas o mesmo carácter.",
    "t_repeat_block": "Não repitas pedaços da senha.",
    "t_keyboard": "Foge de padrões do teclado, como qwerty.",
    "t_year": "Não uses datas de nascimento nem anos.",
    "too_short": "É demasiado curta.",
    "t_short": "Usa pelo menos 12 carácteres. O tamanho é o que mais ajuda.",
    "shortish": "Podia ser mais comprida (o ideal são 12 ou mais carácteres).",
    "leet": "Trocar letras por símbolos (a por @, o por 0) não engana ninguém: os hackers já testam isso.",
    "t_leet": "Em vez de trocar letras, junta várias palavras sem relação entre si.",
    "word_digits": "Uma palavra com uns números no fim é um truque muito comum.",
    "g_length": "Bom tamanho: {n} carácteres.",
    "g_notcommon": "Não é uma das senhas mais populares.",
    "g_phrase": "Parece uma frase de {n} palavras. Boa ideia!",
    "t_phrase": "Junta mais palavras aleatórias à frase (4 ou 5 é o ideal).",
    "g_nopatterns": "Não encontrámos padrões previsíveis.",
    "t_generate": "Usa o botão GERAR para criar uma senha forte e guarda-a num gestor de senhas.",
    "t_unique": "Usa uma senha diferente em cada conta.",
    "d_less": "menos de 1 segundo",
    "d_about": "cerca de {n} {unit}",
    "d_millions": "cerca de {n} milhões de anos",
    "d_billion": "mais de mil milhões de anos",
}
