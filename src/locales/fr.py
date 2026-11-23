"""Français."""

NAME = "Français"
RTL = False


def plural(n: int) -> int:
    return 0 if n <= 1 else 1


UNITS = [("an", "ans"), ("jour", "jours"), ("heure", "heures"),
         ("minute", "minutes"), ("seconde", "secondes")]

STRINGS = {
    "subtitle": "> découvre si ton mot de passe résiste à un pirate",
    "prompt": "root@toi:~$ tape ton mot de passe",
    "show": "afficher", "hide": "masquer",
    "privacy": "Tout reste sur ton ordinateur. Rien n'est envoyé ni enregistré.",
    "gen": "GÉNÉRER UN MOT DE PASSE FORT", "copy": "COPIER", "clear": "EFFACER",
    "idle_headline": "Tape un mot de passe ci-dessus pour commencer.",
    "idle_1": "L'analyse apparaît ici pendant que tu tapes.",
    "idle_2": "Astuce : inutile d'utiliser ton vrai mot de passe. Essaie-en un semblable pour voir comment ça marche.",
    "crack": "Un pirate avec un ordinateur puissant le trouverait en : {time}",
    "hdr_bad": "[ CE QUI NE VA PAS ]", "hdr_good": "[ CE QUI EST BIEN ]", "hdr_tips": "[ COMMENT AMÉLIORER ]",
    "st_generated": "Mot de passe créé ! Copie-le et garde-le en lieu sûr.",
    "st_copied": "Copié ! Il sera effacé du presse-papiers dans 30 secondes.",
    "st_empty": "Tu n'as pas encore tapé de mot de passe.",
    "v1": "TRÈS FAIBLE", "v2": "FAIBLE", "v3": "MOYEN", "v4": "FORT", "v5": "TRÈS FORT",
    "h1": "Un pirate pourrait entrer dans ce compte presque instantanément.",
    "h2": "Ça demande un peu d'effort à un pirate, mais pas beaucoup.",
    "h3": "Résiste aux attaques simples, mais peut être amélioré.",
    "h4": "Bon mot de passe ! Il sera difficile à deviner.",
    "h5": "Excellent ! Pratiquement impossible à deviner.",
    "p_common": "C'est l'un des mots de passe les plus utilisés au monde. Les pirates les essaient en premier.",
    "p_word": "Il contient des mots courants, faciles à deviner.",
    "p_sequence": "Il contient des suites prévisibles (comme 123 ou abc).",
    "p_repeat_char": "Il répète le même caractère plusieurs fois (comme aaa ou 111).",
    "p_repeat_block": "Il répète le même morceau plusieurs fois (comme abcabc).",
    "p_keyboard": "Il suit des touches alignées du clavier (comme qwerty ou azerty).",
    "p_year": "Il contient une année (comme 1998 ou 2024), facile à deviner.",
    "t_common": "Choisis quelque chose que tu n'as jamais vu dans une liste de mots de passe populaires.",
    "t_word": "Évite les mots courants, les prénoms et tout ce qu'on trouve avec une recherche rapide.",
    "t_sequence": "Évite les suites comme 123 ou abc.",
    "t_repeat_char": "Ne répète pas le même caractère.",
    "t_repeat_block": "Ne répète pas des morceaux du mot de passe.",
    "t_keyboard": "Évite les motifs du clavier comme qwerty.",
    "t_year": "N'utilise ni dates de naissance ni années.",
    "too_short": "Il est beaucoup trop court.",
    "t_short": "Utilise au moins 12 caractères. La longueur est ce qui aide le plus.",
    "shortish": "Il pourrait être plus long (idéalement 12 caractères ou plus).",
    "leet": "Remplacer des lettres par des symboles (a par @, o par 0) ne trompe personne : les pirates l'essaient déjà.",
    "t_leet": "Au lieu de remplacer des lettres, assemble plusieurs mots sans rapport entre eux.",
    "word_digits": "Un mot suivi de quelques chiffres est une astuce très courante.",
    "g_length": "Bonne longueur : {n} caractères.",
    "g_notcommon": "Ce n'est pas l'un des mots de passe les plus populaires.",
    "g_phrase": "On dirait une phrase de {n} mots. Bonne idée !",
    "t_phrase": "Ajoute d'autres mots au hasard à la phrase (4 ou 5, c'est l'idéal).",
    "g_nopatterns": "Nous n'avons trouvé aucun motif prévisible.",
    "t_generate": "Utilise le bouton GÉNÉRER pour créer un mot de passe fort et garde-le dans un gestionnaire de mots de passe.",
    "t_unique": "Utilise un mot de passe différent pour chaque compte.",
    "d_less": "moins d'une seconde",
    "d_about": "environ {n} {unit}",
    "d_millions": "environ {n} millions d'années",
    "d_billion": "plus d'un milliard d'années",
}
