"""BrandShield AI - lean MVP backend (FastAPI + RapidFuzz + NetworkX)."""
import os, re, json, urllib.request
from itertools import combinations
from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field
from rapidfuzz import fuzz
from dotenv import load_dotenv
load_dotenv()
import networkx as nx
api_key = os.getenv("AI_API_KEY")

app = FastAPI(title="BrandShield AI")
H0, V1, V2 = "f0e1d2c3b4a59687", "f0e1d2c3b4a59680", "f0e1d2c3b4a59698"
OFF = dict(name="ABC Bank", website="https://www.abcbank.example", domain="abcbank.example",
  desc="ABC Bank offers secure personal banking, savings, loans and cards. Visit our branches or use our official mobile app.",
  usernames={"abcbank"}, pkg="com.abcbank.mobile", dev="ABC Bank Technologies", app_name="ABC Bank Mobile", hash=H0)
LEVELS = [(75, "CRITICAL"), (50, "HIGH"), (25, "MEDIUM"), (0, "LOW")]  # configurable thresholds
W = dict(name=25, logo=20, desc=15, intent=15, dev=10, dom=10)
KW = ["official support", "customer care", "customer support", "verify account", "verify your account", "verify now", "otp",
      "password", "login", "payment", "refund", "claim reward", "reward", "urgent", "contact us", "account suspended", "security verification"]
T = lambda i, k, p, n, u, **x: dict(id=i, kind=k, platform=p, name=n, username=u, package=x.get("pkg"), url=x.get("url"),
  domain=x.get("dom"), description=x.get("desc", ""), developer=x.get("dev"), hash=x.get("h"), age=x.get("age", 1), status="NEW")
SEED = [
 T(1,"social","Instagram","ABC Bank Customer Support","abc_bank_support",url="instagram.com/abc_bank_support",dom="abcbank-help.example",h=V1,age=1,desc="Official support for ABC Bank customers. Verify your account now by sending OTP. Urgent account suspended issues, contact us."),
 T(2,"social","Facebook","ABC Bank Customer Care","abcbankcare",url="facebook.com/abcbankcare",dom="abcbank-help.example",h=V1,age=2,desc="ABC Bank customer care. Verify account with password login to avoid account suspended. Contact us urgent."),
 T(3,"social","X","ABC Bank Rewards","abcbank_rewards",url="x.com/abcbank_rewards",dom="abcbank-rewards.example",h=V2,age=4,desc="Claim reward from ABC Bank! Payment refund and bonus, verify now."),
 T(4,"social","LinkedIn","ABC Bank Help Desk","abcbankhelpdesk",url="linkedin.com/company/abcbankhelpdesk",h=None,age=9,desc="Help desk for ABC Bank customers. Contact us for banking help and login questions."),
 T(5,"social","Instagram","ABC Bank Fans","abcbankfans",url="instagram.com/abcbankfans",h="0123456789abcdef",age=12,desc="Fan page for people who love the ads and community events."),
 T(6,"social","Instagram","ABC Bank","abcbank",url="instagram.com/abcbank",h=H0,age=30,desc="ABC Bank offers secure personal banking, savings, loans and cards."),
 T(7,"app","Google Play","ABC Bank Secure","com.abcsecure.app",pkg="com.abcsecure.app",dev="Unknown Developer",dom="abcbank-help.example",h=V1,age=1,desc="Secure banking with ABC Bank. Login with password, verify account via OTP."),
 T(8,"app","Google Play","ABCBank Mobile Pro","com.abcpro.mobile",pkg="com.abcpro.mobile",dev="Mobile Pro Labs",h=V2,age=6,desc="Banking app for ABC Bank accounts, savings and cards."),
 T(9,"app","Google Play","ABC Bank Customer Care","com.abccare.app",pkg="com.abccare.app",dev="Unknown Developer",dom="abcbank-help.example",h=V2,age=3,desc="Customer care: verify now with OTP, urgent refund support."),
 T(10,"app","App Store","ABC Bank Rewards","com.rewards.abc",pkg="com.rewards.abc",dev="Reward Apps Ltd",dom="abcbank-rewards.example",h=V2,age=5,desc="Claim reward points and cashback with payment refund."),
 T(11,"app","Google Play","ABC Bank Mobile","com.abcbank.mobile",pkg="com.abcbank.mobile",dev="ABC Bank Technologies",h=H0,age=60,desc="ABC Bank offers secure personal banking, savings, loans and cards. Official mobile app."),
]

def norm(s): return re.sub(r"\s+", " ", re.sub(r"[_\-\.@]", " ", (s or "").lower())).strip()
def level(r): return next(l for t, l in LEVELS if r >= t)
def name_sim(a, b):
    a, b = norm(a), norm(b)
    if not a or not b: return 0
    return round(max(fuzz.ratio(a.replace(" ", ""), b.replace(" ", "")), 0.9 * fuzz.token_set_ratio(a, b)))
def logo_sim(h1, h2):
    try: return round(100 * (1 - bin(int(h1, 16) ^ int(h2, 16)).count("1") / 64))  # perceptual-hash Hamming similarity
    except Exception: return None
def desc_sim(a, b): return round(fuzz.token_sort_ratio(norm(a), norm(b))) if a and b else None
def intent(text):
    hits = [k for k in KW if k in (text or "").lower()]
    return min(100, 22 * len(hits)) , hits
def is_official(c):
    u = norm(c.get("username") or "").replace(" ", "")
    if c["kind"] == "social": return u in OFF["usernames"]
    return c.get("package") == OFF["pkg"] and c.get("developer") == OFF["dev"]

def analyze(c):
    if is_official(c):
        return dict(official=True, risk=0, level="OFFICIAL", signals={}, evidence=["✓ Verified Official Asset — exact match to registered official account/app"], compared_against=OFF["name"])
    refs = [OFF["name"], OFF["app_name"]]
    n = max(name_sim(x, r) for x in [c.get("name"), c.get("username")] for r in refs)
    lg = logo_sim(c.get("hash"), OFF["hash"])
    ds = desc_sim(c.get("description"), OFF["desc"])
    it, hits = intent(f'{c.get("name","")} {c.get("description","")}')
    dev = (100 if c.get("developer") != OFF["dev"] else 0) if c.get("developer") else None
    dom = (100 if not c["domain"].endswith(OFF["domain"]) else 0) if c.get("domain") else None
    sig = dict(name=n, logo=lg, desc=ds, intent=it, dev=dev, dom=dom)
    avail = {k: v for k, v in sig.items() if v is not None}  # missing signals are re-normalised, not penalised
    risk = sum(v * W[k] for k, v in avail.items()) / sum(W[k] for k in avail)
    strong = sum([n >= 80, (lg or 0) >= 75, it >= 40, dev == 100, dom == 100])
    if strong < 2: risk = min(risk, 49)  # anti-false-positive: need corroborating signals
    risk = round(risk)
    ev = [f"{n}% name similarity to '{OFF['name']}'"]
    if lg is not None: ev.append(f"{lg}% logo similarity (perceptual hash)")
    else: ev.append("Logo similarity: not available")
    if ds is not None: ev.append(f"{ds}% description similarity")
    ev.append(f"Impersonation intent {it}/100" + (f" — language: {', '.join(hits)}" if hits else ""))
    if dev == 100: ev.append(f"Developer '{c['developer']}' does not match official developer '{OFF['dev']}'")
    if dom == 100: ev.append(f"External domain {c['domain']} differs from official {OFF['domain']}")
    ev.append("Not listed as an official asset")
    if strong < 2: ev.append("Fewer than 2 strong independent signals — risk capped to avoid a false positive")
    return dict(official=False, risk=risk, level=level(risk), signals=sig, evidence=ev, keywords=hits, compared_against=OFF["name"])

THREATS = [{**t, **analyze(t)} for t in SEED]

def build_dna():
    cand = [t for t in THREATS if not t["official"] and t["risk"] >= 25]
    G = nx.Graph(); edges = []
    for a, b in combinations(cand, 2):
        s, why = 0, []
        if a["domain"] and a["domain"] == b["domain"]: s += 30; why.append(f"same domain {a['domain']}")
        if a["hash"] and a["hash"] == b["hash"]: s += 25; why.append("same logo hash")
        elif (logo_sim(a["hash"], b["hash"]) or 0) >= 85: s += 15; why.append("similar logo")
        if a["developer"] and a["developer"] == b["developer"]: s += 15; why.append("same developer")
        if (desc_sim(a["description"], b["description"]) or 0) >= 55: s += 10; why.append("similar description")
        if name_sim(a["name"], b["name"]) >= 70: s += 5; why.append("similar name")
        score = round(s / 85 * 100)
        if score >= 60: G.add_edge(a["id"], b["id"], score=score, why=why); edges.append(dict(source=a["id"], target=b["id"], score=score, why=why))
    out = []
    for i, comp in enumerate(sorted(nx.connected_components(G), key=len, reverse=True), 1):
        es = [d["score"] for _, _, d in G.subgraph(comp).edges(data=True)]
        ids = sorted(comp); dna = round(sum(es) / len(es))
        doms = {t["domain"] for t in THREATS if t["id"] in ids and t["domain"]}
        out.append(dict(id=i, name=f"ABC Bank Impersonation Campaign #{i:02d}", label=f"THREAT DNA #{i:03d} — Possible Coordinated Impersonation Campaign",
          dna_score=dna, risk_level=level(max(t["risk"] for t in THREATS if t["id"] in ids)), members=ids, domains=sorted(doms),
          edges=[e for e in edges if e["source"] in comp]))
    return out
CAMPAIGNS = build_dna()

def public(t): return {k: v for k, v in t.items()}
@app.get("/api/brand")
def brand(): return {k: (sorted(v) if isinstance(v, set) else v) for k, v in OFF.items()}
@app.get("/api/threats")
def threats(kind: str = "", level: str = ""):
    r = [t for t in THREATS if (not kind or t["kind"] == kind) and (not level or t["level"] == level)]
    return sorted(r, key=lambda t: -t["risk"])
@app.get("/api/threats/{tid}")
def threat(tid: int):
    t = next((x for x in THREATS if x["id"] == tid), None)
    if not t: raise HTTPException(404, "Threat not found")
    camp = next((c for c in CAMPAIGNS if tid in c["members"]), None)
    return {**t, "campaign": camp, "related": [x for x in THREATS if camp and x["id"] in camp["members"] and x["id"] != tid]}
class Status(BaseModel): status: str = Field(pattern="^(NEW|INVESTIGATING|REVIEWED|WATCHLIST)$")
@app.post("/api/threats/{tid}/status")
def set_status(tid: int, s: Status):
    t = next((x for x in THREATS if x["id"] == tid), None)
    if not t: raise HTTPException(404, "Threat not found")
    t["status"] = s.status; return {"ok": True}
@app.get("/api/threat-dna")
def dna(): return CAMPAIGNS
@app.get("/api/dashboard")
def dash():
    th = [t for t in THREATS if not t["official"]]
    cnt = lambda f: sum(1 for t in th if f(t))
    return dict(total=len(th), official_excluded=len(THREATS) - len(th), campaigns=len(CAMPAIGNS),
      levels={l: cnt(lambda t, l=l: t["level"] == l) for _, l in LEVELS},
      platforms={p: cnt(lambda t, p=p: t["platform"] == p) for p in sorted({t["platform"] for t in th})},
      trend={"Today": cnt(lambda t: t["age"] <= 1), "Last 7 days": cnt(lambda t: t["age"] <= 7), "Last 30 days": cnt(lambda t: t["age"] <= 30)})

class Check(BaseModel):
    value: str = Field(min_length=1, max_length=300)
    name: str = Field("", max_length=200); url: str = Field("", max_length=300)
    description: str = Field("", max_length=1000); developer: str = Field("", max_length=200); platform: str = Field("", max_length=50)
PROMPT = ("You are a cautious digital safety advisor. Analyze the structured evidence. Do not invent facts. Do not claim certainty unless "
  "official_match is true. Distinguish observed evidence from interpretation. Never request passwords, OTPs, PINs or payment info. If evidence is "
  "insufficient say it cannot be verified. Return JSON with keys: verdict, confidence, summary, reasons, recommended_action, customer_advice.")
def ai_explain(ev):
    key = os.getenv("AI_API_KEY")
    if not key: return None
    try:
        body = json.dumps(dict(model=os.getenv("AI_MODEL", "gpt-4o-mini"), response_format={"type": "json_object"},
          messages=[{"role": "system", "content": PROMPT}, {"role": "user", "content": json.dumps(ev)}])).encode()
        rq = urllib.request.Request(os.getenv("AI_BASE_URL", "https://api.openai.com/v1") + "/chat/completions", body,
          {"Content-Type": "application/json", "Authorization": f"Bearer {key}"})
        return json.loads(json.load(urllib.request.urlopen(rq, timeout=15))["choices"][0]["message"]["content"])
    except Exception: return None
ADVICE = ["Verify the account/app through ABC Bank's official website.", "Do not click suspicious links.", "Do not share OTPs, passwords, PINs or payment information."]
@app.post("/api/safety-check")
def safety(c: Check):
    v = c.value.strip(); vn = norm(v).replace(" ", "")
    known = next((t for t in THREATS if vn and vn in (norm(t["username"] or "").replace(" ", ""), norm(t["name"]).replace(" ", ""), norm(t["url"] or "").replace(" ", ""))), None)
    cand = dict(known) if known else dict(kind="app" if "." in v and "/" not in v and " " not in v and not v.startswith("@") else "social",
      name=c.name or v.lstrip("@"), username=v.lstrip("@"), package=v if "." in v else None, url=c.url or None, description=c.description,
      developer=c.developer or None, hash=None, domain=None)
    if c.url and not known:
        m = re.search(r"(?:https?://)?([^/\s]+)", c.url); cand["domain"] = m.group(1).lower() if m else None
        if cand["domain"] and cand["domain"].endswith(("instagram.com", "facebook.com", "x.com", "linkedin.com", "play.google.com")): cand["domain"] = None
    a = analyze(cand)
    if a["official"]: verdict, summary = "OFFICIAL", "Exact match to a registered official ABC Bank asset."
    elif a["signals"].get("name", 0) < 45 and a["risk"] < 25: verdict, summary = "UNABLE_TO_VERIFY", "There is not enough information to determine whether this entity is legitimate. Verify it through the organization's official website."
    else: verdict, summary = a["level"] + "_RISK", {"CRITICAL": "High-risk indicators detected — likely brand impersonation.", "HIGH": "Multiple indicators of possible impersonation.", "MEDIUM": "Potentially suspicious; some look-alike indicators present.", "LOW": "Few risk indicators, but this could not be verified as official."}[a["level"]]
    ev = dict(brand=OFF["name"], candidate_name=cand["name"], platform=c.platform or cand.get("platform"), **{f"{k}_similarity": v for k, v in a["signals"].items() if k in ("name", "logo", "desc")},
      intent_score=a["signals"].get("intent"), official_match=a["official"], suspicious_indicators=a.get("keywords", []), risk_score=a["risk"])
    ai = ai_explain(ev)
    res = dict(verdict=verdict, risk_score=a["risk"], risk_level=a["level"], evidence=a["evidence"], ai_used=bool(ai),
      summary=(ai or {}).get("summary", summary), recommended_action=(ai or {}).get("recommended_action", "Do not share OTPs, passwords, PINs or payment information."),
      customer_advice=(ai or {}).get("customer_advice", ADVICE), reasons=(ai or {}).get("reasons", a["evidence"]),
      notice=None if ai else "AI explanation unavailable — showing deterministic security analysis.")
    return res

@app.get("/")
def index(): return FileResponse(os.path.join(os.path.dirname(__file__), "index.html"))
