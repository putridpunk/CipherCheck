"""Español."""

NAME = "Español"
RTL = False


def plural(n: int) -> int:
    return 0 if n == 1 else 1


UNITS = [("año", "años"), ("día", "días"), ("hora", "horas"),
         ("minuto", "minutos"), ("segundo", "segundos")]

STRINGS = {
    "subtitle": "> descubre si tu contraseña resiste a un hacker",
    "prompt": "root@tu:~$ escribe tu contraseña",
    "show": "mostrar", "hide": "ocultar",
    "privacy": "Todo se queda en tu ordenador. No se envía ni se guarda nada.",
    "gen": "GENERAR CONTRASEÑA FUERTE", "copy": "COPIAR", "clear": "BORRAR",
    "idle_headline": "Escribe una contraseña arriba para empezar.",
    "idle_1": "El análisis aparece aquí mientras escribes.",
    "idle_2": "Consejo: no hace falta que uses tu contraseña real. Prueba una parecida para ver cómo funciona.",
    "crack": "Un hacker con un ordenador potente la descubriría en: {time}",
    "hdr_bad": "[ LO QUE ESTÁ MAL ]", "hdr_good": "[ LO QUE ESTÁ BIEN ]", "hdr_tips": "[ CÓMO MEJORAR ]",
    "st_generated": "¡Contraseña creada! Cópiala y guárdala en un lugar seguro.",
    "st_copied": "¡Copiado! Se borrará del portapapeles en 30 segundos.",
    "st_empty": "Todavía no has escrito ninguna contraseña.",
    "st_similar": "¡Hemos creado una versión fuerte de tu contraseña! Cópiala y guárdala en un lugar seguro.",
    "st_already": "Tu contraseña ya es fuerte. La dejamos como está.",
    "v1": "MUY DÉBIL", "v2": "DÉBIL", "v3": "ACEPTABLE", "v4": "FUERTE", "v5": "MUY FUERTE",
    "h1": "Un hacker podría entrar en esta cuenta casi al instante.",
    "h2": "A un hacker le costaría algo de trabajo, pero no mucho.",
    "h3": "Aguanta ataques simples, pero se puede mejorar.",
    "h4": "¡Buena contraseña! Será difícil de adivinar.",
    "h5": "¡Excelente! Prácticamente imposible de adivinar.",
    "p_common": "Es una de las contraseñas más usadas del mundo. Los hackers prueban estas primero.",
    "p_word": "Contiene palabras normales, que son fáciles de adivinar.",
    "p_sequence": "Tiene secuencias previsibles (como 123 o abc).",
    "p_repeat_char": "Repite el mismo carácter varias veces (como aaa o 111).",
    "p_repeat_block": "Repite el mismo trozo varias veces (como abcabc).",
    "p_keyboard": "Sigue teclas seguidas del teclado (como qwerty o asdf).",
    "p_year": "Contiene un año (como 1998 o 2024), algo fácil de adivinar.",
    "t_common": "Elige algo que nunca hayas visto en una lista de contraseñas populares.",
    "t_word": "Evita palabras cotidianas, nombres y cualquier cosa que se encuentre con una búsqueda rápida.",
    "t_sequence": "Huye de secuencias como 123 o abc.",
    "t_repeat_char": "No repitas el mismo carácter.",
    "t_repeat_block": "No repitas trozos de la contraseña.",
    "t_keyboard": "Evita patrones del teclado como qwerty.",
    "t_year": "No uses fechas de nacimiento ni años.",
    "too_short": "Es demasiado corta.",
    "t_short": "Usa al menos 12 caracteres. La longitud es lo que más ayuda.",
    "shortish": "Podría ser más larga (lo ideal son 12 o más caracteres).",
    "leet": "Cambiar letras por símbolos (a por @, o por 0) no engaña a nadie: los hackers ya lo prueban.",
    "t_leet": "En vez de cambiar letras, junta varias palabras sin relación entre sí.",
    "word_digits": "Una palabra con unos números al final es un truco muy común.",
    "g_length": "Buena longitud: {n} caracteres.",
    "g_notcommon": "No es una de las contraseñas más populares.",
    "g_phrase": "Parece una frase de {n} palabras. ¡Buena idea!",
    "t_phrase": "Añade más palabras al azar a la frase (lo ideal son 4 o 5).",
    "g_nopatterns": "No hemos encontrado patrones previsibles.",
    "t_generate": "Usa el botón GENERAR para crear una contraseña fuerte y guárdala en un gestor de contraseñas.",
    "t_unique": "Usa una contraseña distinta en cada cuenta.",
    "d_less": "menos de 1 segundo",
    "d_about": "unos {n} {unit}",
    "d_millions": "unos {n} millones de años",
    "d_billion": "más de mil millones de años",
}
