"""LightScan v2.0 PHANTOM — Mutation Engine | Developer: Light"""
import itertools

LEET = str.maketrans("aAeEiIoOsS", "4433110055")
SUFFIXES = ["!","@","#","1","01","123","1234","12345","!1","2021","2022","2023","2024","2025","!!","?","$","99","_",".*"]

COMMON_PASSWORDS = [
    "password","Password1","Password1!","123456","12345678","admin","Admin123",
    "Admin1234!","welcome","Welcome1","changeme","ChangeMe123!","letmein","qwerty",
    "abc123","iloveyou","monkey","dragon","master","P@ssw0rd","P@$$w0rd",
    "Passw0rd!","Summer2024!","Winter2024!","Spring2024!","Company123!",
    "Welcome2024!","Login2024!","root","toor","admin123","administrator",
    "test","test123","guest","guest123","service","support","backup",
    "","pass","login","1234","111111","000000","password123","12341234",
    "superman","batman","football","baseball","letmein1","sunshine","princess",
    "shadow","master1","hello","hello123","welcome123","abc","qwerty123",
]

class MutationEngine:
    def __init__(self, base_words=None, target_info=None, max_per_base=60, include_common=True):
        self.base_words=base_words or []; self.target_info=target_info or {}
        self.max_per_base=max_per_base; self.include_common=include_common

    def _variants(self, word):
        yield word
        yield word.lower(); yield word.upper(); yield word.capitalize(); yield word.swapcase()
        yield word.translate(LEET)
        yield word[::-1]
        for s in SUFFIXES:
            yield word+s; yield word.capitalize()+s; yield word.upper()+s
        for yr in range(2019,2026):
            yield f"{word}{yr}"; yield f"{word.capitalize()}{yr}!"; yield f"{word}{yr}!"
        yield f"{word.capitalize()}@123"; yield f"{word.capitalize()}#1"
        yield f"!{word}"; yield f"{word}!!"

    def _ctx(self):
        extra=[]
        for key in ("domain","company","service","hostname","org"):
            val=self.target_info.get(key,"")
            if val:
                base=val.split(".")[0] if "." in val else val
                extra.extend([base,base.lower(),base.capitalize(),base.upper()])
        return extra

    def generate(self, username="", extra_words=None):
        seen=set(); result=[]
        words = self.base_words + self._ctx() + (extra_words or [])

        if self.include_common:
            for p in COMMON_PASSWORDS:
                if p not in seen: seen.add(p); result.append(p)

        if username:
            for s in SUFFIXES[:10]:
                for cand in (username+s, username.capitalize()+s):
                    if cand not in seen: seen.add(cand); result.append(cand)
            for yr in range(2020,2026):
                cand=f"{username}{yr}"
                if cand not in seen: seen.add(cand); result.append(cand)

        for base in words:
            count=0
            for v in self._variants(base):
                if v and v not in seen and count < self.max_per_base:
                    seen.add(v); result.append(v); count+=1

        for w1, w2 in itertools.combinations(words[:10], 2):
            for cand in (f"{w1.capitalize()}{w2}", f"{w1}{w2.capitalize()}123"):
                if cand not in seen: seen.add(cand); result.append(cand)

        return result

    @staticmethod
    def load_wordlist(path, limit=200000):
        words=[]
        try:
            with open(path, encoding="utf-8", errors="ignore") as f:
                for line in f:
                    w=line.strip()
                    if w: words.append(w)
                    if len(words)>=limit: break
        except FileNotFoundError:
            print(f"\033[38;5;196m[!]\033[0m Wordlist not found: {path}")
        return words
