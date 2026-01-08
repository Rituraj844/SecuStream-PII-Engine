import re
import hashlib
import json
import csv
import os
from typing import List, Dict, Any


def detect_sensitive_data(text: str) -> List[Dict[str, Any]]:
    """
    Scan a text string and return a list of detected sensitive entities.
    Detects email, IPv4, credit card, phone numbers, and simple names.
    """
    if not text:
        return []

    entities: List[Dict[str, Any]] = []

    patterns = {
        "email": re.compile(r"[\w.\-+%]+@[\w.\-]+\.[A-Za-z]{2,}", re.IGNORECASE),
        "ipv4": re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
        "credit_card": re.compile(r"\b(?:\d[ -]*?){13,19}\b"),
        "phone": re.compile(r"\b(?:\+?\d{1,3}[ -]?)?(?:\d{10,12})\b"),
        "name": re.compile(r"\b([A-Z][a-z]+(?:\s+[A-Z][a-z]+)+)\b")
    }

    for etype, pat in patterns.items():
        for m in pat.finditer(text):
            matched = m.group(0)
            if etype == "credit_card":
                digits = re.sub(r"[^0-9]", "", matched)
                if len(digits) < 13 or len(digits) > 19:
                    continue
            if etype == "ipv4":
                octs = matched.split(".")
                if len(octs) != 4 or any(not (0 <= int(o) <= 255) for o in octs):
                    continue
            entities.append({
                "type": etype,
                "match": matched,
                "start": m.start(),
                "end": m.end()
            })

    entities.sort(key=lambda e: e["start"])
    return entities


def mask_data(entities: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Deterministic masking with SHA-256.
    Same input -> same masked output.
    """
    salt = os.environ.get("SECUSTREAM_SALT", "secustream_default_salt").encode("utf-8")

    def _hash_value(val: str) -> str:
        h = hashlib.sha256()
        h.update(salt)
        normalized = " ".join(val.split())
        h.update(normalized.encode("utf-8"))
        return "sha256_" + h.hexdigest()[:16]

    masked_list: List[Dict[str, Any]] = []
    seen = {}
    for ent in entities:
        orig = ent.get("match")
        if orig in seen:
            masked = seen[orig]
        else:
            masked = _hash_value(orig)
            seen[orig] = masked
        masked_list.append({
            "type": ent.get("type"),
            "original": orig,
            "masked": masked
        })

    return masked_list


def generate_safe_output(file_path: str) -> Dict[str, Any]:
    """
    Process CSV, JSON, or text logs and generate masked output + audit report.
    """
    audit = {
        "input_path": file_path,
        "masked_path": None,
        "audit_path": None,
        "total_cells_or_strings": 0,
        "masked_count": 0,
        "masked_by_type": {}
    }

    basename, ext = os.path.splitext(file_path)
    ext = ext.lower()

    def _record_masking(masked_items: List[Dict[str, Any]]):
        for m in masked_items:
            audit["masked_count"] += 1
            audit["masked_by_type"][m["type"]] = audit["masked_by_type"].get(m["type"], 0) + 1

    if ext in (".csv", ".tsv"):
        out_path = f"{basename}_masked{ext}"
        delimiter = '\t' if ext == '.tsv' else ','
        with open(file_path, newline='', encoding='utf-8') as inf, \
             open(out_path, 'w', newline='', encoding='utf-8') as outf:
            reader = csv.reader(inf, delimiter=delimiter)
            writer = csv.writer(outf, delimiter=delimiter)
            for row in reader:
                new_row = []
                for cell in row:
                    audit["total_cells_or_strings"] += 1
                    if cell is None:
                        new_row.append(cell)
                        continue
                    ents = detect_sensitive_data(str(cell))
                    if not ents:
                        new_row.append(cell)
                        continue
                    masked_list = mask_data(ents)
                    _record_masking(masked_list)
                    masked_cell = str(cell)
                    for m in masked_list:
                        masked_cell = re.sub(re.escape(m["original"]), m["masked"], masked_cell)
                    new_row.append(masked_cell)
                writer.writerow(new_row)
        audit["masked_path"] = out_path

    elif ext == ".json":
        out_path = f"{basename}_masked.json"

        def _walk_and_mask(obj):
            if isinstance(obj, str):
                audit["total_cells_or_strings"] += 1
                ents = detect_sensitive_data(obj)
                if not ents:
                    return obj
                masked = mask_data(ents)
                _record_masking(masked)
                new = obj
                for m in masked:
                    new = re.sub(re.escape(m["original"]), m["masked"], new)
                return new
            elif isinstance(obj, list):
                return [_walk_and_mask(x) for x in obj]
            elif isinstance(obj, dict):
                return {k: _walk_and_mask(v) for k, v in obj.items()}
            else:
                return obj

        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        masked_data = _walk_and_mask(data)
        with open(out_path, 'w', encoding='utf-8') as f:
            json.dump(masked_data, f, ensure_ascii=False, indent=2)
        audit["masked_path"] = out_path

    else:
        out_path = f"{basename}_masked{ext or '.masked.txt'}"
        with open(file_path, 'r', encoding='utf-8') as inf, \
             open(out_path, 'w', encoding='utf-8') as outf:
            for line in inf:
                audit["total_cells_or_strings"] += 1
                ents = detect_sensitive_data(line)
                if ents:
                    masked = mask_data(ents)
                    _record_masking(masked)
                    new = line
                    for m in masked:
                        new = re.sub(re.escape(m["original"]), m["masked"], new)
                    outf.write(new)
                else:
                    outf.write(line)
        audit["masked_path"] = out_path

    audit_path = f"{basename}_audit.json"
    with open(audit_path, 'w', encoding='utf-8') as af:
        json.dump(audit, af, ensure_ascii=False, indent=2)
    audit["audit_path"] = audit_path

    return audit