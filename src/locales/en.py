"""English (master locale: every other locale must define the same keys)."""

NAME = "English"
RTL = False


def plural(n: int) -> int:
    return 0 if n == 1 else 1


UNITS = [("year", "years"), ("day", "days"), ("hour", "hours"),
         ("minute", "minutes"), ("second", "seconds")]

STRINGS = {
    "subtitle": "> find out if your password can stand up to a hacker",
    "prompt": "root@you:~$ type your password",
    "show": "show", "hide": "hide",
    "privacy": "Everything stays on your computer. Nothing is sent or saved.",
    "gen": "GENERATE STRONG PASSWORD", "copy": "COPY", "clear": "CLEAR",
    "idle_headline": "Type a password above to get started.",
    "idle_1": "The analysis appears here as you type.",
    "idle_2": "Tip: you don't need to use your real password. Try a similar one to see how it works.",
    "crack": "A hacker with a powerful computer would crack it in: {time}",
    "hdr_bad": "[ WHAT'S WRONG ]", "hdr_good": "[ WHAT'S GOOD ]", "hdr_tips": "[ HOW TO IMPROVE ]",
    "st_generated": "Password created! Copy it and keep it somewhere safe.",
    "st_copied": "Copied! It will be cleared from the clipboard in 30 seconds.",
    "st_empty": "You haven't typed a password yet.",
    "st_similar": "Made a strong version of your password! Copy it and keep it somewhere safe.",
    "st_already": "Your password is already strong. Kept as it is.",
    "v1": "VERY WEAK", "v2": "WEAK", "v3": "FAIR", "v4": "STRONG", "v5": "VERY STRONG",
    "h1": "A hacker could get into this account almost instantly.",
    "h2": "It takes a hacker some effort, but not much.",
    "h3": "Holds up against simple attacks, but it can be better.",
    "h4": "Nice password! It will be hard to guess.",
    "h5": "Excellent! Practically impossible to guess.",
    "p_common": "It's one of the most used passwords in the world. Hackers try these first.",
    "p_word": "It contains ordinary words, which are easy to guess.",
    "p_sequence": "It has predictable sequences (like 123 or abc).",
    "p_repeat_char": "It repeats the same character several times (like aaa or 111).",
    "p_repeat_block": "It repeats the same chunk several times (like abcabc).",
    "p_keyboard": "It follows keys in a row on the keyboard (like qwerty or asdf).",
    "p_year": "It contains a year (like 1998 or 2024), which is easy to guess.",
    "t_common": "Pick something you've never seen on a list of popular passwords.",
    "t_word": "Avoid everyday words, names and anything you could find with a quick search.",
    "t_sequence": "Stay away from sequences like 123 or abc.",
    "t_repeat_char": "Don't repeat the same character.",
    "t_repeat_block": "Don't repeat chunks of the password.",
    "t_keyboard": "Avoid keyboard patterns like qwerty.",
    "t_year": "Don't use birth dates or years.",
    "too_short": "It's far too short.",
    "t_short": "Use at least 12 characters. Length is what helps most.",
    "shortish": "It could be longer (12 or more characters is ideal).",
    "leet": "Swapping letters for symbols (a for @, o for 0) fools nobody: hackers already try that.",
    "t_leet": "Instead of swapping letters, combine several unrelated words.",
    "word_digits": "A word with a few numbers at the end is a very common trick.",
    "g_length": "Good length: {n} characters.",
    "g_notcommon": "It isn't one of the most popular passwords.",
    "g_phrase": "It looks like a phrase of {n} words. Good idea!",
    "t_phrase": "Add more random words to the phrase (4 or 5 is ideal).",
    "g_nopatterns": "We found no predictable patterns.",
    "t_generate": "Use the GENERATE button to create a strong password and keep it in a password manager.",
    "t_unique": "Use a different password for every account.",
    "d_less": "less than 1 second",
    "d_about": "about {n} {unit}",
    "d_millions": "about {n} million years",
    "d_billion": "more than a billion years",
}
