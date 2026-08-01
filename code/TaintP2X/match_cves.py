
import json
import urllib.request
import urllib.error
import argparse

def get_osv_vulnerabilities(package_name, ecosystem="PyPI"):
    """Fetch known vulnerabilities for a package using the OSV.dev API (which includes NVD CVEs)."""
    url = "https://api.osv.dev/v1/query"
    data = json.dumps({
        "package": {
            "name": package_name,
            "ecosystem": ecosystem
        }
    }).encode('utf-8')
    
    req = urllib.request.Request(url, data=data, headers={'Content-Type': 'application/json'})
    try:
        with urllib.request.urlopen(req) as response:
            result = json.loads(response.read().decode())
            return result.get("vulns", [])
    except urllib.error.URLError as e:
        print(f"Error querying OSV API: {e}")
        return []

def extract_callables_from_pysa(pysa_output_file):
    """Extract all unique 'callable' paths that Pysa flagged as issues."""
    callables = set()
    try:
        with open(pysa_output_file, 'r') as f:
            # taint-output.json is often JSON-lines format
            for line in f:
                line = line.strip()
                if not line: continue
                try:
                    finding = json.loads(line)
                    if finding.get("kind") == "issue":
                        callable_name = finding.get("data", {}).get("callable")
                        if callable_name:
                            callables.add(callable_name)
                except json.JSONDecodeError:
                    continue
    except FileNotFoundError:
        print(f"File not found: {pysa_output_file}")
    return callables

def map_findings_to_cves(callables, vulns):
    """Attempt to map the Pysa callables to the text descriptions of the CVEs."""
    mapping = []
    
    # 1. Dynamically calculate generic terms based on statistical frequency
    # This makes the script work for ANY repository automatically!
    keyword_counts = {}
    for c in callables:
        # Split the path into words
        parts = c.replace('_', '.').split('.')
        for p in parts:
            if len(p) > 3:
                keyword_counts[p.lower()] = keyword_counts.get(p.lower(), 0) + 1
                
    # If a word appears in > 10% of findings, it is a structural word for this repo 
    # (e.g. 'langchain', 'chains', 'base') and must be ignored to prevent false matches.
    threshold = max(2, len(callables) * 0.1)
    dynamic_ignore_list = {k for k, v in keyword_counts.items() if v > threshold}
    
    # Add a few absolute Python default methods to ignore
    dynamic_ignore_list.update({'__call__', '__init__', 'parse', 'generate', 'predict', 'apply'})

    # 2. Extract highly specific search terms for each callable
    search_terms = {}
    for c in callables:
        parts = c.split('.')
        # Look backwards through the path to find the first highly specific, rare class/function name
        for part in reversed(parts):
            clean_part = part.strip('_')
            if len(clean_part) > 4 and clean_part.lower() not in dynamic_ignore_list:
                search_terms[c] = clean_part
                break

    for vuln in vulns:
        details = vuln.get("details", "")
        summary = vuln.get("summary", "")
        aliases = vuln.get("aliases", []) # This contains the actual CVE IDs (e.g. CVE-2023-1234)
        
        # Combine summary and details for searching
        full_text = f"{summary} {details}".lower()
        
        matched_callables = []
        for c, keyword in search_terms.items():
            # If the class name (like LLMMathChain) is explicitly mentioned in the CVE description
            if keyword.lower() in full_text:
                matched_callables.append(c)
                
        if matched_callables:
            mapping.append({
                "cves": aliases,
                "osv_id": vuln.get("id"),
                "summary": summary,
                "matched_pysa_findings": matched_callables
            })
            
    return mapping

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Map Pysa findings to known CVEs using OSV.dev")
    parser.add_argument("--file", required=True, help="Path to taint-output.json")
    parser.add_argument("--package", required=True, help="Package name (e.g., langchain)")
    
    args = parser.parse_args()
    
    print(f"[*] Extracting findings from {args.file}...")
    callables = extract_callables_from_pysa(args.file)
    print(f"[*] Found {len(callables)} unique callables flagged by Pysa.")
    
    print(f"\n[*] Querying OSV/NVD database for known vulnerabilities in '{args.package}'...")
    vulns = get_osv_vulnerabilities(args.package)
    print(f"[*] Found {len(vulns)} officially reported vulnerabilities (CVEs/Advisories).")
    
    print("\n[*] Mapping findings to CVEs based on textual analysis...")
    mapped_results = map_findings_to_cves(callables, vulns)
    
    # --- Deduplication ---
    # The OSV API returns the same CVE from multiple sources (e.g. OSV + NVD mirror),
    # causing duplicate entries. Deduplicate by CVE ID, preferring the entry with a summary.
    seen_cves = {}
    for match in mapped_results:
        cve_ids = [a for a in match['cves'] if a.startswith('CVE')]
        key = tuple(sorted(cve_ids)) if cve_ids else match['osv_id']
        if key not in seen_cves:
            seen_cves[key] = match
        else:
            # Prefer the entry that has a non-empty summary
            if not seen_cves[key]['summary'] and match['summary']:
                seen_cves[key] = match
    deduped_results = list(seen_cves.values())

    if not deduped_results:
        print("\n[-] No direct mappings found. This means the CVE descriptions in NVD didn't mention the exact class names flagged by Pysa.")
    else:
        print(f"\n--- SUCCESS: MATCHES FOUND ({len(deduped_results)} unique CVEs) ---")
        for match in deduped_results:
            cve_list = [a for a in match['cves'] if a.startswith('CVE')]
            display_id = ', '.join(cve_list) if cve_list else match['osv_id']
            print(f"\n[+] Vulnerability: {display_id}")
            print(f"    Summary: {match['summary']}")
            print(f"    Matched Pysa Findings:")
            for mc in match['matched_pysa_findings']:
                print(f"      - {mc}")

