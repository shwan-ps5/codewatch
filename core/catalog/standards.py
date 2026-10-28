"""Free standards data: MITRE CWE (incl. the Top 25 and the OWASP Top 10 mapping) and W3C WCAG 2.2."""
import io
import json
import re
import xml.etree.ElementTree as ET
import zipfile

CWE_XML_URL = "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip"
WCAG_JSON_URL = "https://www.w3.org/WAI/WCAG22/wcag.json"
TOP25_VIEW = "1435"
OWASP_VIEW = "1450"
BLOCK_TAGS = {"div", "p", "li", "ul", "ol", "br", "pre"}
MAX_MITIGATIONS = 4
MAX_EXAMPLES = 2


def local(tag):
    return tag.rsplit("}", 1)[-1]


def xhtml_text(element):
    """Text of a CWE XHTML fragment, keeping line breaks so example code stays readable."""
    if element is None:
        return ""
    parts = []

    def walk(node):
        if node.text:
            parts.append(node.text)
        for child in node:
            walk(child)
            if local(child.tag) in BLOCK_TAGS:
                parts.append("\n")
            if child.tail:
                parts.append(child.tail)

    walk(element)
    text = "\n".join(line.rstrip() for line in "".join(parts).splitlines())
    return re.sub(r"\n{3,}", "\n\n", text).strip()


class Cwe:
    def __init__(self, xml_zip):
        with zipfile.ZipFile(io.BytesIO(xml_zip)) as z:
            self.root = ET.fromstring(z.read(next(n for n in z.namelist() if n.endswith(".xml"))))
        self.ns = {"c": self.root.tag.split("}")[0][1:]}
        self.weaknesses = {int(w.get("ID")): w for w in self.root.iterfind(".//c:Weakness", self.ns)}

    def find(self, path, node=None):
        return (node if node is not None else self.root).iterfind(path, self.ns)

    def parents(self, weakness):
        return sorted({int(r.get("CWE_ID")) for r in self.find(".//c:Related_Weakness", weakness)
                       if r.get("Nature") == "ChildOf" and r.get("View_ID") == "1000"})

    def owasp_categories(self, views):
        groupings = {g.get("ID"): g for g in self.find(".//c:Grouping")}
        out = []
        for member in self.find(".//c:Has_Member", views[OWASP_VIEW]):
            g = groupings[member.get("CWE_ID")]
            code, _, title = g.get("Name").split("Category ", 1)[1].partition(" - ")
            out.append({"id": code, "name": title, "cwe_grouping": int(g.get("ID")),
                        "cwes": sorted(int(m.get("CWE_ID")) for m in self.find(".//c:Has_Member", g)),
                        "url": "https://owasp.org/Top10/2025/"})
        return out

    def summary(self):
        views = {v.get("ID"): v for v in self.find(".//c:View")}
        parents = {wid: self.parents(w) for wid, w in self.weaknesses.items()}
        return {
            "source": "MITRE CWE (https://cwe.mitre.org), used under the CWE Terms of Use",
            "cwe_version": self.root.get("Version"),
            "cwe_date": self.root.get("Date"),
            "top25": {"name": views[TOP25_VIEW].get("Name"), "view": int(TOP25_VIEW),
                      "cwes": [int(m.get("CWE_ID")) for m in self.find(".//c:Has_Member", views[TOP25_VIEW])],
                      "url": "https://cwe.mitre.org/top25/"},
            "owasp": {"name": "OWASP Top 10 (2025)", "view": int(OWASP_VIEW),
                      "categories": self.owasp_categories(views)},
            "cwe_names": {str(k): w.get("Name") for k, w in sorted(self.weaknesses.items())},
            "cwe_parents": {str(k): v for k, v in sorted(parents.items()) if v},
        }

    def details(self, cwe_id):
        """What's wrong, how to fix it and example code for one weakness, from MITRE's entry."""
        w = self.weaknesses.get(cwe_id)
        if w is None:
            return None
        mitigations = [{"phase": ", ".join(p.text for p in self.find("c:Phase", m)),
                        "text": xhtml_text(m.find("c:Description", self.ns))}
                       for m in self.find("c:Potential_Mitigations/c:Mitigation", w)][:MAX_MITIGATIONS]
        return {
            "description": xhtml_text(w.find("c:Description", self.ns)),
            "extended": xhtml_text(w.find("c:Extended_Description", self.ns))[:1500],
            "mitigations": [m for m in mitigations if m["text"]],
            "examples": [self.example(e) for e in self.find("c:Demonstrative_Examples/c:Demonstrative_Example", w)
                         ][:MAX_EXAMPLES],
            "url": f"https://cwe.mitre.org/data/definitions/{cwe_id}.html",
        }

    def example(self, node):
        codes = [{"language": c.get("Language", ""), "nature": c.get("Nature", ""), "code": xhtml_text(c)}
                 for c in self.find("c:Example_Code", node)]
        return {"intro": xhtml_text(node.find("c:Intro_Text", self.ns)), "code": codes,
                "body": " ".join(xhtml_text(b) for b in self.find("c:Body_Text", node))[:1200]}


def wcag(wcag_json):
    data = json.loads(wcag_json)
    return {
        "name": "WCAG 2.2",
        "source": "W3C Web Content Accessibility Guidelines 2.2 (https://www.w3.org/TR/WCAG22/), W3C Document License",
        "criteria": [
            {"sc": sc["num"], "title": sc["handle"], "level": sc["level"],
             "url": f"https://www.w3.org/WAI/WCAG22/Understanding/{sc['id']}.html"}
            for p in data["principles"] for g in p["guidelines"] for sc in g["successcriteria"]
            if "2.2" in sc.get("versions", ["2.2"])
        ],
    }
