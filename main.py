LOAD_CCI = r"C:\Users\joshu\OneDrive\Documents\CODING PROJECTS\CSE 484 Project\CCI_List.xml" #Put your CCI list filepath here
LOAD_STIG = r"C:\Users\joshu\OneDrive\Documents\CODING PROJECTS\CSE 484 Project\U_MS_Windows_11_STIG_V2R11_Manual-xccdf.xml" #Put your STIG filepath here

REVISION = 'title="NIST SP 800-53 Revision 5"'

#reads the CCI file and builds a dictionary that maps each CCI number to its definition, status and NIST codes.
# 1.    text.split(start, 1) cuts the text at the first <status>, giving ['', 'draft</status>']. 
#       (The 1 cuts at the first match)
# 2.     [1] keeps the part after the marker: 'draft</status>'.
# 3.     .split(end, 1)[0] cuts that at </status> and keeps the part before it: 'draft'.
def between(text, start, end):
    return text.split(start, 1)[1].split(end, 1)[0]

# reads the CCI list and returns with a dictionary (lookup) of each CCI number's definition, status, and NIST code
def load_cci_lookup(path):
    text = open(path, encoding="utf-8-sig").read() # loads the CCI list into one big string
    lookup = {}
    for item in text.split("<cci_item ")[1:]: # cuts the string into one piece per CCI
        refs = item.split("<reference ")[1:] # further cuts those pieces into one piece per NIST reference
        lookup[between(item, 'id="', '"')] = {

            "definition": between(item, "<definition>", "</definition>"), 
            "status": between(item, "<status>", "</status>"),
            "nist": [between(r, 'index="', '"') for r in refs if REVISION in r],

            }
    return lookup #each CCI number now has a NIST code assigned to it in lookup

# reads the STIG file and returns a list of its rules. 
# Each rule is a dictionary with a V-ID, STIG ID, severity, title and CCIs.
def load_stig(path):
    text = open(path, encoding="utf-8-sig").read() # loads the STIG file into one big string
    rules = []
    for group in text.split('<Group id="')[1:]: # grabs the V-ID
        rule = group.split("<Rule ", 1)[1] #
        idents = [between(x, ">", "<") for x in rule.split("<ident")[1:]] # Get the text inside every <ident> tag; these hold CCIs and old V-IDs
        rules.append({
            "vuln_id": group.split('"', 1)[0],
            "stig_id": between(rule, "<version>", "</version>"),
            "severity": between(rule, 'severity="', '"'),
            "title": between(rule, "<title>", "</title>"),
            "ccis": [i for i in idents if i.startswith("CCI-")],
        })
    return rules

# links every STIG rule to its NIST controls through its CCIs. 
# It produces one row per link and marks anything that can’t be linked.
def connect(rules, lookup):
    rows = []
    for rule in rules:
        def add(cci, nist, note):

            # adds a row with the rule's V-ID, STIG ID and severity, plus the CCI, NIST code and note passed in, and the rule's title
            rows.append({"vuln_id": rule["vuln_id"], "stig_id": rule["stig_id"], "severity": rule["severity"],
                         "cci": cci, "nist": nist, "family": nist[:2], "note": note, "title": rule["title"]})
         
        if not rule["ccis"]: # checks whether the rule lists no CCIs at all   
            add("", "", "NO CCI") # if it doesnt, it adds a row with the mark NO CCI with blank CCI and NIST columns

        for cci in rule["ccis"]:
            info = lookup.get(cci)
            if info is None: 
                add(cci, "", "CCI NOT IN LIST") # if the CCI isn't in the lookup dictionary, adds a row flagged CCI NOT IN LIST
            elif not info["nist"]:
                add(cci, "", "NO REV 5 CODE") # same as above but for NISTs
            else:
                for code in info["nist"]: # in the case where both are in the dictionary, adds one row per NIST code, with no note
                    add(cci, code, "")
    return rows

#writes all rows to a csv
def save_csv(rows, path):
    with open(path, "w", encoding="utf-8-sig") as f:
        f.write(",".join(rows[0]) + "\n")
        for row in rows:
            f.write(",".join('"' + v.replace('"', '""') + '"' for v in row.values()) + "\n")

lookup = load_cci_lookup(LOAD_CCI)
rules = load_stig(LOAD_STIG)
rows = connect(rules, lookup)
save_csv(rows, "output.csv")



# #prints the rows in the terminal, grouped by control family, with problem rows in a NEEDS REVIEW group at the end.
# def display(rows):
#     groups = {}
#     for row in rows:
#         family = row["nist"][:2] if row["nist"] else "NEEDS REVIEW"
#         groups.setdefault(family, []).append(row)
#     for family in sorted(groups, key=lambda f: (f == "NEEDS REVIEW", f)):  # NEEDS REVIEW last
#         print(f"\n=== {family} ({len(groups[family])}) ===")
#         for row in groups[family]:
#             print(f"{row['vuln_id']:<10}{row['stig_id']:<17}{row['severity']:<8}{row['cci']:<12}"
#                   f"{row['nist'] or row['note']:<18}{row['title'][:45]}")

