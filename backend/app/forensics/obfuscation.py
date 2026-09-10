"""
MailRecon AI — Unicode, Homoglyph & Evasive Obfuscation Engine
Detects zero-width steganography, Right-to-Left Override (RLO) spoofing,
and mixed-script homoglyph substitution used by adversaries to evade detection.
"""

from dataclasses import dataclass, field
import re
import unicodedata
from typing import Any, Dict, List, Set, Tuple

# Set of invisible / zero-width characters used to break keyword pattern matching
ZERO_WIDTH_CHARS: Dict[str, str] = {
    "\u200B": "ZERO WIDTH SPACE",
    "\u200C": "ZERO WIDTH NON-JOINER",
    "\u200D": "ZERO WIDTH JOINER",
    "\u200E": "LEFT-TO-RIGHT MARK",
    "\u200F": "RIGHT-TO-LEFT MARK",
    "\uFEFF": "ZERO WIDTH NO-BREAK SPACE (BOM)",
    "\u2060": "WORD JOINER",
    "\u2062": "INVISIBLE TIMES",
    "\u2063": "INVISIBLE SEPARATOR",
    "\u2064": "INVISIBLE PLUS",
    "\u00AD": "SOFT HYPHEN",
    "\u2800": "BRAILLE PATTERN BLANK",
}

# Right-to-Left Override (RLO) & Bidirectional control characters
BIDI_OVERRIDE_CHARS: Dict[str, str] = {
    "\u202E": "RIGHT-TO-LEFT OVERRIDE (RLO)",
    "\u202D": "LEFT-TO-RIGHT OVERRIDE (LRO)",
    "\u202A": "LEFT-TO-RIGHT EMBEDDING (LRE)",
    "\u202B": "RIGHT-TO-LEFT EMBEDDING (RLE)",
    "\u202C": "POP DIRECTIONAL FORMATTING (PDF)",
    "\u2066": "LEFT-TO-RIGHT ISOLATE (LRI)",
    "\u2067": "RIGHT-TO-LEFT ISOLATE (RLI)",
    "\u2068": "FIRST STRONG ISOLATE (FSI)",
    "\u2069": "POP DIRECTIONAL ISOLATE (PDI)",
}

# Comprehensive lookalike homoglyph mapping to canonical ASCII
HOMOGLYPH_MAP: Dict[str, str] = {
    # Cyrillic lowercase
    "\u0430": "a", "\u0441": "c", "\u0435": "e", "\u043E": "o",
    "\u0440": "p", "\u0455": "s", "\u0445": "x", "\u0443": "y",
    "\u0456": "i", "\u0458": "j", "\u0501": "d", "\u051B": "q",
    # Cyrillic uppercase
    "\u0410": "A", "\u0412": "B", "\u0421": "C", "\u0415": "E",
    "\u041D": "H", "\u0406": "I", "\u0408": "J", "\u041A": "K",
    "\u041C": "M", "\u041D": "H", "\u041E": "O", "\u0420": "P",
    "\u0422": "T", "\u0425": "X", "\u0423": "Y",
    # Greek lowercase
    "\u03B1": "a", "\u03B2": "b", "\u03B5": "e", "\u03BF": "o",
    "\u03BD": "v", "\u03C1": "p", "\u03C4": "t", "\u03C5": "u",
    "\u03BA": "k", "\u03B9": "i", "\u03C9": "w",
    # Greek uppercase
    "\u0391": "A", "\u0392": "B", "\u0395": "E", "\u0397": "H",
    "\u0399": "I", "\u039A": "K", "\u039C": "M", "\u039D": "N",
    "\u039F": "O", "\u03A1": "P", "\u03A4": "T", "\u03A7": "X",
    "\u03A5": "Y", "\u0396": "Z",
}

# Full-width ASCII characters (\uFF01 - \uFF5E)
for code in range(0xFF01, 0xFF5F):
    HOMOGLYPH_MAP[chr(code)] = chr(code - 0xFEE0)


@dataclass
class DeobfuscationResult:
    original_text: str
    normalized_text: str
    has_evasion: bool = False
    zero_width_count: int = 0
    zero_width_chars: List[Dict[str, Any]] = field(default_factory=list)
    rlo_detected: bool = False
    rlo_chars: List[Dict[str, Any]] = field(default_factory=list)
    homoglyphs_detected: bool = False
    homoglyphs_found: List[Dict[str, Any]] = field(default_factory=list)
    mixed_script_tokens: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "original_preview": self.original_text[:200],
            "normalized_preview": self.normalized_text[:200],
            "has_evasion": self.has_evasion,
            "zero_width_count": self.zero_width_count,
            "zero_width_chars": self.zero_width_chars,
            "rlo_detected": self.rlo_detected,
            "rlo_chars": self.rlo_chars,
            "homoglyphs_detected": self.homoglyphs_detected,
            "homoglyphs_found": self.homoglyphs_found,
            "mixed_script_tokens": self.mixed_script_tokens,
        }


class ObfuscationAnalyzer:
    """
    Forensic analyzer for detecting adversarial obfuscation techniques
    embedded in text, headers, and filenames.
    """

    @classmethod
    def analyze_text(cls, text: str) -> DeobfuscationResult:
        """
        Analyze a string for zero-width characters, RLO overrides, and homoglyphs.
        Returns a DeobfuscationResult with normalized text.
        """
        if not text:
            return DeobfuscationResult(original_text="", normalized_text="")

        zero_width_found: List[Dict[str, Any]] = []
        rlo_found: List[Dict[str, Any]] = []
        homoglyphs_found: List[Dict[str, Any]] = []

        normalized_chars: List[str] = []

        for idx, ch in enumerate(text):
            # 1. Check for Zero-Width / Invisible characters
            if ch in ZERO_WIDTH_CHARS:
                zero_width_found.append({
                    "char": ch,
                    "name": ZERO_WIDTH_CHARS[ch],
                    "codepoint": f"U+{ord(ch):04X}",
                    "position": idx,
                })
                # Skip in normalized output to rebuild clean keyword
                continue

            # 2. Check for RLO / BiDi overrides
            if ch in BIDI_OVERRIDE_CHARS:
                rlo_found.append({
                    "char": ch,
                    "name": BIDI_OVERRIDE_CHARS[ch],
                    "codepoint": f"U+{ord(ch):04X}",
                    "position": idx,
                })
                # Skip in normalized output
                continue

            # 3. Check for Homoglyphs
            if ch in HOMOGLYPH_MAP:
                canonical = HOMOGLYPH_MAP[ch]
                homoglyphs_found.append({
                    "char": ch,
                    "canonical": canonical,
                    "codepoint": f"U+{ord(ch):04X}",
                    "unicode_name": unicodedata.name(ch, "UNKNOWN"),
                    "position": idx,
                })
                normalized_chars.append(canonical)
                continue

            normalized_chars.append(ch)

        normalized_str = "".join(normalized_chars)

        # 4. Check for mixed-script tokens in words
        mixed_script_tokens = cls._find_mixed_script_tokens(text)

        has_evasion = bool(
            zero_width_found or rlo_found or homoglyphs_found or mixed_script_tokens
        )

        return DeobfuscationResult(
            original_text=text,
            normalized_text=normalized_str,
            has_evasion=has_evasion,
            zero_width_count=len(zero_width_found),
            zero_width_chars=zero_width_found[:50],  # cap list for serialization
            rlo_detected=bool(rlo_found),
            rlo_chars=rlo_found,
            homoglyphs_detected=bool(homoglyphs_found),
            homoglyphs_found=homoglyphs_found[:50],
            mixed_script_tokens=mixed_script_tokens,
        )

    @classmethod
    def _find_mixed_script_tokens(cls, text: str) -> List[str]:
        """
        Identify tokens that blend Latin characters with Cyrillic or Greek characters.
        Legitimate words almost never mix Latin letters with Cyrillic lookalikes.
        """
        tokens = re.findall(r'[a-zA-Z\u0400-\u04FF\u0370-\u03FF0-9_\-\.]+', text)
        mixed: List[str] = []

        for token in tokens:
            has_latin = False
            has_non_latin = False
            for ch in token:
                cp = ord(ch)
                if (65 <= cp <= 90) or (97 <= cp <= 122):
                    has_latin = True
                elif (0x0400 <= cp <= 0x04FF) or (0x0370 <= cp <= 0x03FF):
                    has_non_latin = True

            if has_latin and has_non_latin:
                if token not in mixed:
                    mixed.append(token)

        return mixed

    @classmethod
    def inspect_filename(cls, filename: str) -> Tuple[bool, str, Optional[str]]:
        """
        Specialized inspection for attachment filenames.
        Detects Right-To-Left Override (U+202E) hiding executable extensions.
        Returns: (is_evasive, sanitized_filename, detected_trick_description)
        """
        if not filename:
            return False, filename, None

        if "\u202E" in filename or any(c in filename for c in BIDI_OVERRIDE_CHARS):
            # Reconstruct what the user sees vs actual physical extension
            clean_name = "".join(c for c in filename if c not in BIDI_OVERRIDE_CHARS)
            return True, clean_name, "Right-To-Left Override (RLO) extension masquerading attack"

        # Check for homoglyph extensions, e.g., .ехе with Cyrillic 'е'
        res = cls.analyze_text(filename)
        if res.has_evasion and res.homoglyphs_detected:
            return True, res.normalized_text, "Homoglyph extension masquerading attack"

        return False, filename, None
