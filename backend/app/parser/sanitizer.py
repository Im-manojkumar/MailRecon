import re
from typing import Tuple, List
import bleach

ALLOWED_TAGS = [
    "p", "b", "i", "u", "em", "strong", "a", "br",
    "table", "thead", "tbody", "tr", "td", "th",
    "ul", "ol", "li", "span", "div", "blockquote",
    "h1", "h2", "h3", "h4", "h5", "h6", "pre", "code",
    "hr", "img"
]

ALLOWED_ATTRIBUTES = {
    "*": ["class", "id", "title", "dir", "lang"],
    "a": ["href", "title", "target", "rel"],
    "img": ["src", "alt", "title", "width", "height", "data-original-src", "data-blocked"],
    "td": ["colspan", "rowspan", "align"],
    "th": ["colspan", "rowspan", "align"],
}

ALLOWED_PROTOCOLS = ["http", "https", "mailto", "cid", "data"]

PLACEHOLDER_IMG = "data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' width='120' height='24'><rect width='100%' height='100%' fill='%23222'/><text x='5' y='16' fill='%23bbb' font-family='sans-serif' font-size='11'>[Remote Image]</text></svg>"


def sanitize_html(raw_html: str) -> Tuple[str, List[str]]:
    """
    Sanitize untrusted HTML from email body.
    - Strips scripts, iframes, styles, and dangerous attributes.
    - Neutralizes remote HTTP/HTTPS images to prevent tracking pixels / remote loading.
    - Preserves cid: inline image references.
    - Returns (sanitized_html, list_of_blocked_remote_image_urls).
    """
    if not raw_html:
        return "", []

    blocked_images: List[str] = []

    # First pass: identify and neutralize remote image sources
    def neutralize_img_src(match):
        full_tag = match.group(0)
        src_match = re.search(r'src=["\']([^"\']+)["\']', full_tag, re.IGNORECASE)
        if src_match:
            src = src_match.group(1).strip()
            # If remote http/https or protocol-relative, neutralize it
            if src.lower().startswith(("http://", "https://", "//")):
                blocked_images.append(src)
                # Replace src with placeholder and save original in data attribute
                new_tag = re.sub(
                    r'src=["\'][^"\']+["\']',
                    f'src="{PLACEHOLDER_IMG}" data-original-src="{src}" data-blocked="true"',
                    full_tag,
                    flags=re.IGNORECASE
                )
                return new_tag
        return full_tag

    # Replace <img> tags with remote sources
    preprocessed_html = re.sub(r'<img\b[^>]*>', neutralize_img_src, raw_html, flags=re.IGNORECASE)

    # Use bleach to strictly sanitize HTML
    cleaned = bleach.clean(
        preprocessed_html,
        tags=ALLOWED_TAGS,
        attributes=ALLOWED_ATTRIBUTES,
        protocols=ALLOWED_PROTOCOLS,
        strip=True,
        strip_comments=True
    )

    return cleaned, blocked_images
