"""Deutsch."""

NAME = "Deutsch"
RTL = False


def plural(n: int) -> int:
    return 0 if n == 1 else 1


UNITS = [("Jahr", "Jahre"), ("Tag", "Tage"), ("Stunde", "Stunden"),
         ("Minute", "Minuten"), ("Sekunde", "Sekunden")]

STRINGS = {
    "subtitle": "> finde heraus, ob dein Passwort einem Hacker standhält",
    "prompt": "root@du:~$ gib dein Passwort ein",
    "show": "zeigen", "hide": "verbergen",
    "privacy": "Alles bleibt auf deinem Computer. Nichts wird gesendet oder gespeichert.",
    "gen": "STARKES PASSWORT ERZEUGEN", "copy": "KOPIEREN", "clear": "LEEREN",
    "idle_headline": "Gib oben ein Passwort ein, um zu starten.",
    "idle_1": "Die Analyse erscheint hier, während du tippst.",
    "idle_2": "Tipp: Du musst nicht dein echtes Passwort verwenden. Probiere ein ähnliches aus.",
    "crack": "Ein Hacker mit einem leistungsstarken Computer knackt es in: {time}",
    "hdr_bad": "[ WAS NICHT STIMMT ]", "hdr_good": "[ WAS GUT IST ]", "hdr_tips": "[ SO WIRD ES BESSER ]",
    "st_generated": "Passwort erstellt! Kopiere es und bewahre es sicher auf.",
    "st_copied": "Kopiert! Es wird in 30 Sekunden aus der Zwischenablage gelöscht.",
    "st_empty": "Du hast noch kein Passwort eingegeben.",
    "v1": "SEHR SCHWACH", "v2": "SCHWACH", "v3": "MITTELMÄSSIG", "v4": "STARK", "v5": "SEHR STARK",
    "h1": "Ein Hacker käme fast sofort in dieses Konto.",
    "h2": "Ein Hacker braucht etwas Aufwand, aber nicht viel.",
    "h3": "Hält einfachen Angriffen stand, aber es geht besser.",
    "h4": "Gutes Passwort! Es ist schwer zu erraten.",
    "h5": "Ausgezeichnet! Praktisch unmöglich zu erraten.",
    "p_common": "Es ist eines der meistgenutzten Passwörter der Welt. Hacker probieren diese zuerst.",
    "p_word": "Es enthält gewöhnliche Wörter, die leicht zu erraten sind.",
    "p_sequence": "Es enthält vorhersehbare Folgen (wie 123 oder abc).",
    "p_repeat_char": "Es wiederholt dasselbe Zeichen mehrmals (wie aaa oder 111).",
    "p_repeat_block": "Es wiederholt denselben Abschnitt mehrmals (wie abcabc).",
    "p_keyboard": "Es folgt Tasten in einer Reihe auf der Tastatur (wie qwertz oder asdf).",
    "p_year": "Es enthält eine Jahreszahl (wie 1998 oder 2024), die leicht zu erraten ist.",
    "t_common": "Wähle etwas, das du noch nie auf einer Liste beliebter Passwörter gesehen hast.",
    "t_word": "Meide Alltagswörter, Namen und alles, was man mit einer schnellen Suche findet.",
    "t_sequence": "Meide Folgen wie 123 oder abc.",
    "t_repeat_char": "Wiederhole nicht dasselbe Zeichen.",
    "t_repeat_block": "Wiederhole keine Teile des Passworts.",
    "t_keyboard": "Meide Tastaturmuster wie qwertz.",
    "t_year": "Verwende keine Geburtsdaten oder Jahreszahlen.",
    "too_short": "Es ist viel zu kurz.",
    "t_short": "Verwende mindestens 12 Zeichen. Die Länge hilft am meisten.",
    "shortish": "Es könnte länger sein (ideal sind 12 oder mehr Zeichen).",
    "leet": "Buchstaben durch Symbole zu ersetzen (a durch @, o durch 0) täuscht niemanden: Hacker probieren das schon.",
    "t_leet": "Statt Buchstaben zu ersetzen, kombiniere mehrere nicht zusammenhängende Wörter.",
    "word_digits": "Ein Wort mit ein paar Zahlen am Ende ist ein sehr verbreiteter Trick.",
    "g_length": "Gute Länge: {n} Zeichen.",
    "g_notcommon": "Es gehört nicht zu den beliebtesten Passwörtern.",
    "g_phrase": "Es sieht aus wie ein Satz aus {n} Wörtern. Gute Idee!",
    "t_phrase": "Füge dem Satz weitere zufällige Wörter hinzu (4 oder 5 sind ideal).",
    "g_nopatterns": "Wir haben keine vorhersehbaren Muster gefunden.",
    "t_generate": "Nutze die Schaltfläche ERZEUGEN für ein starkes Passwort und bewahre es in einem Passwortmanager auf.",
    "t_unique": "Verwende für jedes Konto ein anderes Passwort.",
    "d_less": "weniger als 1 Sekunde",
    "d_about": "etwa {n} {unit}",
    "d_millions": "etwa {n} Millionen Jahre",
    "d_billion": "mehr als eine Milliarde Jahre",
}
