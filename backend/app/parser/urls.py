import ipaddress
import re
from typing import Any, Dict, List
from urllib.parse import urlparse
from html.parser import HTMLParser

# Regex to detect standard HTTP/HTTPS URLs in plain text
URL_REGEX = re.compile(
    r'(?:https?://|www\.)[a-zA-Z0-9.\-_~:/?#\[\]@!$&\'()*+,;=%]+',
    re.IGNORECASE
)

# Trailing characters that are likely punctuation, not part of URL
TRAILING_PUNCTUATION = '.,;:!?)>"\']'


def defang_url(url: str) -> str:
    """
    Defang a URL for safe display and logging without accidental clicking.
    Examples:
        https://malicious.com/payload -> hxxps://malicious[.]com/payload
        http://192.168.1.1/test -> hxxp://192[.]168[.]1[.]1/test
    """
    defanged = url
    if defanged.lower().startswith("https://"):
        defanged = "hxxps://" + defanged[8:]
    elif defanged.lower().startswith("http://"):
        defanged = "hxxp://" + defanged[7:]

    # Parse and defang the netloc/domain part only
    try:
        parsed = urlparse(url)
        netloc = parsed.netloc
        if netloc:
            defanged_netloc = netloc.replace(".", "[.]")
            # Replace first instance of netloc
            defanged = defanged.replace(netloc, defanged_netloc, 1)
        else:
            defanged = defanged.replace(".", "[.]")
    except Exception:
        defanged = defanged.replace(".", "[.]")

    return defanged


def is_ip_host(hostname: str) -> bool:
    """Determine if a hostname is an IPv4 or IPv6 address."""
    if not hostname:
        return False
    # Strip port if present
    host = hostname.split(":")[0].strip("[]")
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


class AnchorExtractor(HTMLParser):
    """HTML parser to extract <a href="..."> tags with their inner text."""
    def __init__(self):
        super().__init__()
        self.links: List[Dict[str, str]] = []
        self._current_href: str | None = None
        self._current_text: List[str] = []

    def handle_starttag(self, tag, attrs):
        if tag.lower() == "a":
            for name, val in attrs:
                if name.lower() == "href" and val:
                    self._current_href = val.strip()
                    self._current_text = []
                    break

    def handle_data(self, data):
        if self._current_href is not None:
            self._current_text.append(data)

    def handle_endtag(self, tag):
        if tag.lower() == "a" and self._current_href is not None:
            anchor_text = " ".join("".join(self._current_text).split()).strip()
            self.links.append({
                "url": self._current_href,
                "anchor_text": anchor_text
            })
            self._current_href = None
            self._current_text = []


def clean_url(raw_url: str) -> str:
    """Trim leading/trailing whitespace and trailing sentence punctuation."""
    url = raw_url.strip()
    while url and url[-1] in TRAILING_PUNCTUATION:
        url = url[:-1]
    return url


def extract_urls(text_body: str | None, html_body: str | None) -> List[Dict[str, Any]]:
    """
    Extract, normalize, and defang URLs from both plain text and HTML bodies.
    Does NOT resolve or fetch any network resource.
    """
    seen: Dict[str, Dict[str, Any]] = {}

    def record_url(raw_candidate: str, source: str, anchor_text: str | None = None):
        cleaned = clean_url(raw_candidate)
        if not cleaned:
            return

        # Handle schemes
        if cleaned.lower().startswith("www."):
            normalized_url = "http://" + cleaned
        elif cleaned.lower().startswith(("http://", "https://")):
            normalized_url = cleaned
        else:
            return

        try:
            parsed = urlparse(normalized_url)
            hostname = parsed.hostname or ""
        except Exception:
            return

        if not hostname:
            return

        is_ip = is_ip_host(hostname)
        defanged = defang_url(normalized_url)

        key = f"{normalized_url}|{source}"
        if key in seen:
            seen[key]["occurrences"] += 1
        else:
            seen[key] = {
                "url": normalized_url,
                "defanged": defanged,
                "domain": hostname.lower(),
                "is_ip": is_ip,
                "source": source,
                "anchor_text": anchor_text or None,
                "occurrences": 1,
            }

    # 1. Extract from HTML anchors
    if html_body:
        parser = AnchorExtractor()
        try:
            parser.feed(html_body)
            for item in parser.links:
                record_url(item["url"], source="html_anchor", anchor_text=item["anchor_text"])
        except Exception:
            pass

        # Also search raw text inside HTML for plain URLs not wrapped in <a>
        for match in URL_REGEX.finditer(html_body):
            record_url(match.group(0), source="html_text")

    # 2. Extract from Plain text body
    if text_body:
        for match in URL_REGEX.finditer(text_body):
            record_url(match.group(0), source="body_text")

    return list(seen.values())
