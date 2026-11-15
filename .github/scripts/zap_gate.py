"""Security gate DAST : analyse le rapport JSON d'OWASP ZAP et echoue
si au moins une alerte de risque eleve (High) est presente."""
import json
import sys

RISK = {"0": "Info", "1": "Low", "2": "Medium", "3": "High"}
THRESHOLD = 3  # High

report = json.load(open(sys.argv[1] if len(sys.argv) > 1 else "zap-report.json", encoding="utf-8"))
alerts = [a for site in report.get("site", []) for a in site.get("alerts", [])]
alerts.sort(key=lambda a: -int(a["riskcode"]))

print(f"{'RISQUE':<8} {'PLUGIN':<7} {'NB':>3}  ALERTE")
print("-" * 80)
for a in alerts:
    print(f"{RISK[a['riskcode']]:<8} {a['pluginid']:<7} {a['count']:>3}  {a['name']}")
    if int(a["riskcode"]) >= THRESHOLD:
        for inst in a.get("instances", [])[:3]:
            print(f"{'':<20}-> {inst.get('method')} {inst.get('uri')}  param={inst.get('param')}  attack={inst.get('attack')!r}")

blocking = [a for a in alerts if int(a["riskcode"]) >= THRESHOLD]
print("-" * 80)
if blocking:
    print(f"ECHEC DAST : {len(blocking)} alerte(s) de risque HIGH -> deploiement bloque")
    sys.exit(1)
print("DAST OK : aucune alerte de risque HIGH")
