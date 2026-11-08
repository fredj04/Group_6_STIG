LOAD_CCI = r"C:\Users\joshu\OneDrive\Documents\CODING PROJECTS\CSE 484 Project\CCI_List.xml" #Put your CCI list filepath here
LOAD_STIG = r"C:\Users\joshu\OneDrive\Documents\CODING PROJECTS\CSE 484 Project\U_MS_Windows_11_STIG_V2R11_Manual-xccdf.xml" #Put your STIG filepath here

REVISION = 'title="NIST SP 800-53 Revision 5"'

def between(text, start, end):
    return text.split(start, 1)[1].split(end, 1)[0]

def load_cci_lookup(path):
    text = open(path, encoding="utf-8-sig").read()
    lookup = {}
    for item in text.split("<cci_item ")[1:]:
        refs = item.split("<reference ")[1:]
        lookup[between(item, 'id="', '"')] = {"definition": between(item, "<definition>", "</definition>"), 
            "status": between(item, "<status>", "</status>"),"nist": 
            [between(r, 'index="', '"') for r in refs if REVISION in r],}
    return lookup

def load_stig(path):
    text = open(path, encoding="utf-8-sig").read()
    rules = []
    for group in text.split('<Group id="')[1:]:
        rule = group.split("<Rule ", 1)[1]
        idents = [between(x, ">", "<") for x in rule.split("<ident")[1:]]
        rules.append({
            "vuln_id": group.split('"', 1)[0],
            "stig_id": between(rule, "<version>", "</version>"),
            "severity": between(rule, 'severity="', '"'),
            "title": between(rule, "<title>", "</title>"),
            "ccis": [i for i in idents if i.startswith("CCI-")],
        })
    return rules

def connect(rules, lookup):
    rows = []
    for r in rules:
        def add(cci, nist, note):
            rows.append({"vuln_id": r["vuln_id"], "stig_id": r["stig_id"], "severity": r["severity"],
                         "cci": cci, "nist": nist, "note": note, "title": r["title"]})
        if not r["ccis"]:
            add("", "", "NO CCI")
        for cci in r["ccis"]:
            info = lookup.get(cci)
            if info is None:
                add(cci, "", "CCI NOT IN LIST")
            elif not info["nist"]:
                add(cci, "", "NO REV 5 CODE")
            else:
                for code in info["nist"]:
                    add(cci, code, "")
    return rows

def display(rows):
    groups = {}
    for row in rows:
        family = row["nist"][:2] if row["nist"] else "NEEDS REVIEW"
        groups.setdefault(family, []).append(row)
    for family in sorted(groups, key=lambda f: (f == "NEEDS REVIEW", f)):  # NEEDS REVIEW last
        print(f"\n=== {family} ({len(groups[family])}) ===")
        for row in groups[family]:
            print(f"{row['vuln_id']:<10}{row['stig_id']:<17}{row['severity']:<8}{row['cci']:<12}"
                  f"{row['nist'] or row['note']:<18}{row['title'][:45]}")

def save_csv(rows, path):
    with open(path, "w", encoding="utf-8-sig") as f:
        f.write(",".join(rows[0]) + "\n")
        for row in rows:
            f.write(",".join('"' + v.replace('"', '""') + '"' for v in row.values()) + "\n")

lookup = load_cci_lookup(LOAD_CCI)
rules = load_stig(LOAD_STIG)
rows = connect(rules, lookup)
display(rows)
save_csv(rows, "output.csv")

