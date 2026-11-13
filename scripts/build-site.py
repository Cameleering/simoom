#!/usr/bin/env python3
"""Render simoom's docs/**/*.md to static HTML under site/simoom/docs/ for cameleer.ing/simoom/.

Adapted from Cameleer's scripts/build-docs.py (same owner and licence; same markdown renderer,
page conventions, structured data and output layout), so simoom's pages match the main site.
Python 3 standard library only. Output is deterministic (sorted, no timestamps; dates come from
git), and the build fails on broken internal links or anchors.

    python3 scripts/build-site.py                    # docs/ -> site/simoom/docs/
    python3 scripts/build-site.py --preview DIR --cameleer-site PATH
        # also assemble a preview: Cameleer's site with site/simoom/ at /simoom/, so the shared
        # /assets/*.css paths resolve; serve it with `python -m http.server -d DIR`

What it writes (under --out, default site/simoom/):
  docs/**/*.html          one page per markdown file (README.md -> index.html), plus the raw .md
  docs/guides/index.html  the generated guide index
  sitemap.xml             the simoom home page, llms.txt, the designed pages under use-cases/,
                          compare/, alternatives/ and benchmarks/, and every docs page
  llms.txt                site/simoom/llms.txt with its generated "## Documentation" section replaced
  llms-full.txt           every docs page concatenated as plain markdown

The pages live under the main site's host and load its shared assets (/assets/site.css,
/assets/compare.css, /assets/docs.js, the favicons) one level above site/simoom/.

Page conventions: the first line under the H1 is a blockquote that answers the page's question
(it becomes the meta description); "## Common questions" with "### question" headings becomes
FAQPage structured data. STATUS.md, BUGS.md, website-plan.md, benchmark-review.md, design/ and parity/ are working
documents and stay in the repository.
"""

import argparse
import html
import json
import os
import re
import shutil
import subprocess
import sys
import time

# Files that exist only for the Read the Docs build (docs/conf.py), skipped here.
SPHINX_ONLY = {"index.md", "conf.py", "requirements.txt"}
# Working documents for the project (plans and strategy) that stay in the repository only.
INTERNAL = {"website-plan.md", "STATUS.md", "BUGS.md", "benchmark-review.md"}
# Directories of working documents (design notes for planned work, release-note drafts that become
# GitHub Release bodies), also repository only.
INTERNAL_DIRS = {"design", "parity", "release-notes"}

SITE_URL = "https://cameleer.ing/simoom/"
REPO_URL = "https://github.com/Cameleering/simoom"
SITE_NAME = "simoom"

SECTIONS = [  # (directory, nav title, index title, index answer)
    ("guides", "Guides", "Guides",
     "Task-by-task guides for building HTTP services with simoom: routing, slow work, streaming, WebSocket, TLS, HTTP/3, limits and the client."),
]
SECTION_DIRS = [s[0] for s in SECTIONS]

# Guides listed first, in this order (paths under guides/, without .md); the rest follow
# alphabetically by title. Paths, not file stems: guides/mcp/deployment.md is not "deployment".
GUIDE_ORDER = ["getting-started", "services-and-replies", "routing", "slow-work", "streaming-and-sse", "websocket",
               "tls", "http2-and-http3", "limits-and-security", "runtime", "client", "features-and-size",
               "sans-io-crates", "coding-agents", "faq"]

# Pages that moved (old output path -> new output path): the old URL gets a redirect page.
MOVED = {}

CATEGORY_ORDER = [
    "Core and routing", "Scheduling", "Files, shell and streams", "HTTP, REST and web services",
    "Messaging and streaming", "Network protocols", "Mail", "Databases and search",
    "AI and LLMs", "Chat and SaaS", "Amazon Web Services", "Microsoft Azure",
    "Google Cloud and Workspace", "Templating", "XML, JSON and validation", "Other",
]
CATEGORIES = {
    "Core and routing": "bean browse class controlbus dataformat dataset dataset-test direct kamelet language log mock ref saga seda stub test vm",
    "Scheduling": "timer scheduler cron quartz",
    "Files, shell and streams": "file ftp ftps sftp scp ssh exec stream",
    "HTTP, REST and web services": "http https platform-http rest netty-http jetty undertow webhook graphql cxf cxfrs spring-ws fhir websocket ws wss vertx-websocket rss atom",
    "Messaging and streaming": "kafka paho paho-mqtt5 amqp amqp-stomp activemq jms rabbitmq spring-rabbitmq stomp",
    "Network protocols": "netty mllp syslog grpc thrift",
    "Mail": "mail smtp smtps imap imaps pop3 pop3s",
    "Databases and search": "sql sql-stored jdbc mongodb mongodb-gridfs spring-redis redis cql cassandra couchdb elasticsearch opensearch",
    "AI and LLMs": "openai anthropic gemini ai-tool ai-resource ai-prompt mcp aws-bedrock aws-bedrock-agent-runtime aws2-bedrock azure-openai google-vertexai",
    "Chat and SaaS": "slack telegram github jira twilio",
    "Templating": "mustache velocity freemarker string-template mvel",
    "XML, JSON and validation": "xslt xslt-saxon xquery xj validator json-validator xmlsecurity-sign xmlsecurity-verify xmlsecurity",
}
CATEGORY_OF = {name: cat for cat, names in CATEGORIES.items() for name in names.split()}


def category_for(stem, explicit=None):
    if explicit:
        return explicit
    if stem in CATEGORY_OF:
        return CATEGORY_OF[stem]
    if stem.startswith("aws"):
        return "Amazon Web Services"
    if stem.startswith("azure-"):
        return "Microsoft Azure"
    if stem.startswith("google-"):
        return "Google Cloud and Workspace"
    return "Other"


class BuildError(Exception):
    pass


# ---------------------------------------------------------------------------
# Markdown
# ---------------------------------------------------------------------------

def esc(s):
    return html.escape(s, quote=True)


def slugify(text):
    """GitHub-style heading anchor: lowercase, drop punctuation, spaces to hyphens."""
    s = text.strip().lower()
    s = re.sub(r"[^\w\- ]", "", s)
    return s.replace(" ", "-")


def strip_tags(h):
    return html.unescape(re.sub(r"<[^>]+>", "", h))


FENCE_RE = re.compile(r"^( {0,3})(`{3,}|~{3,})(.*)$")
HEADING_RE = re.compile(r"^ {0,3}(#{1,6})(?:[ \t]+(.*?))?(?:[ \t]+#+)?[ \t]*$")
HR_RE = re.compile(r"^ {0,3}([-*_])(?:[ \t]*\1){2,}[ \t]*$")
LIST_RE = re.compile(r"^( {0,3})([-*+]|\d{1,9}[.)])([ \t]+|$)(.*)$")
TABLE_SEP_RE = re.compile(r"^\s*\|?\s*:?-+:?\s*(\|\s*:?-+:?\s*)*\|?\s*$")
MARKER_RE = re.compile(r"^\s*<!--\s*example:\s*(\S+)\s*-->\s*$")
HTML_BLOCK_RE = re.compile(r"^ {0,3}</?(div|table|thead|tbody|tr|td|th|details|summary|p|img|picture|source|section|figure|figcaption|ul|ol|li|pre|h[1-6]|hr|br|dl|dt|dd|center|video|iframe)\b", re.I)
INLINE_TAG_RE = re.compile(r"</?(br|kbd|sub|sup|b|i|em|strong|small|abbr|span|code|mark|del|ins|u|s)(\s[^<>]*)?/?>", re.I)
ENTITY_RE = re.compile(r"&(#\d+|#x[0-9a-fA-F]+|[A-Za-z][A-Za-z0-9]*);")
ALERTS = {"NOTE": "Note", "TIP": "Tip", "IMPORTANT": "Important", "WARNING": "Warning", "CAUTION": "Caution"}
PUNCT = set("!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~")


class Renderer:
    """A small CommonMark/GFM subset: what the docs use, rendered correctly."""

    def __init__(self, link_hook, refs=None):
        self.link_hook = link_hook  # (href) -> href
        self.refs = refs or {}
        self.headings = []  # (level, id, html)
        self.ids = {}

    # ---- inline -------------------------------------------------------------

    def inline(self, s, links=True):
        out = []
        i, n = 0, len(s)
        while i < n:
            c = s[i]
            if c == "\\" and i + 1 < n and s[i + 1] in PUNCT:
                out.append(esc(s[i + 1]))
                i += 2
            elif c == "\\" and i + 1 < n and s[i + 1] == "\n":
                out.append("<br>\n")
                i += 2
            elif c == "`":
                j = i
                while j < n and s[j] == "`":
                    j += 1
                ticks = s[i:j]
                k = j
                end = -1
                while True:
                    k = s.find(ticks, k)
                    if k < 0:
                        break
                    if (k + len(ticks) >= n or s[k + len(ticks)] != "`") and s[k - 1] != "`":
                        end = k
                        break
                    while k < n and s[k] == "`":
                        k += 1
                if end < 0:
                    out.append(esc(ticks))
                    i = j
                else:
                    code = s[j:end].replace("\n", " ")
                    if len(code) > 2 and code[0] == " " and code[-1] == " " and code.strip():
                        code = code[1:-1]
                    out.append("<code>%s</code>" % esc(code))
                    i = end + len(ticks)
            elif c == "!" and i + 1 < n and s[i + 1] == "[" and links:
                r = self.link_at(s, i + 1)
                if r:
                    text, href, title, end = r
                    t = ' title="%s"' % esc(title) if title else ""
                    out.append('<img src="%s" alt="%s"%s loading="lazy">' % (esc(self.link_hook(href)), esc(strip_tags(self.inline(text, False))), t))
                    i = end
                else:
                    out.append("!")
                    i += 1
            elif c == "[" and links:
                r = self.link_at(s, i)
                if r:
                    text, href, title, end = r
                    t = ' title="%s"' % esc(title) if title else ""
                    out.append('<a href="%s"%s>%s</a>' % (esc(self.link_hook(href)), t, self.inline(text, False)))
                    i = end
                else:
                    out.append("[")
                    i += 1
            elif c == "<":
                m = re.match(r"<((?:https?|mailto|ftp):[^\s<>]+)>", s[i:])
                if m and links:
                    u = m.group(1)
                    out.append('<a href="%s">%s</a>' % (esc(u), esc(u)))
                    i += m.end()
                    continue
                if s.startswith("<!--", i):
                    k = s.find("-->", i + 4)
                    i = n if k < 0 else k + 3
                    continue
                m = INLINE_TAG_RE.match(s, i)
                if m:
                    out.append(m.group(0))
                    i = m.end()
                else:
                    out.append("&lt;")
                    i += 1
            elif c == "&":
                m = ENTITY_RE.match(s, i)
                if m:
                    out.append(m.group(0))
                    i = m.end()
                else:
                    out.append("&amp;")
                    i += 1
            elif c in "*_":
                r = self.emphasis(s, i)
                if r:
                    h, i = r
                    out.append(h)
                else:
                    j = i
                    while j < n and s[j] == c:
                        j += 1
                    out.append(s[i:j])
                    i = j
            elif c == "~" and s.startswith("~~", i):
                k = s.find("~~", i + 2)
                if k > i + 2:
                    out.append("<del>%s</del>" % self.inline(s[i + 2:k], links))
                    i = k + 2
                else:
                    out.append("~~")
                    i += 2
            elif c == "h" and links and (i == 0 or not s[i - 1].isalnum() and s[i - 1] not in "/\"'=(") and re.match(r"https?://", s[i:]):
                m = re.match(r"https?://[^\s<>]*[^\s<>.,;:!?\"')\]]", s[i:])
                if m:
                    u = m.group(0)
                    out.append('<a href="%s">%s</a>' % (esc(u), esc(u)))
                    i += m.end()
                else:
                    out.append(c)
                    i += 1
            elif c == "\n":
                if out and out[-1].endswith("  "):
                    out[-1] = out[-1].rstrip(" ")
                    out.append("<br>\n")
                else:
                    out.append("\n")
                i += 1
            else:
                out.append(esc(c))
                i += 1
        return "".join(out)

    def emphasis(self, s, i):
        c = s[i]
        n = len(s)
        j = i
        while j < n and s[j] == c:
            j += 1
        run = j - i
        if j >= n or s[j].isspace():
            return None
        if c == "_" and i > 0 and s[i - 1].isalnum():
            return None
        for size in ([2, 1] if run >= 2 else [1]):
            delim = c * size
            k = i + size
            while True:
                k = s.find(delim, k)
                if k < 0:
                    break
                if k == i + size or s[k - 1].isspace():
                    k += 1
                    continue
                if s[i + size:k].count("`") % 2 == 1:  # the closer is inside a code span
                    k += 1
                    continue
                if size == 1 and s[k + 1:k + 2] == c:  # part of a `**` closer
                    k += 2
                    continue
                if c == "_" and k + size < n and s[k + size].isalnum():  # intraword underscore
                    k += size
                    continue
                tag = "strong" if size == 2 else "em"
                return "<%s>%s</%s>" % (tag, self.inline(s[i + size:k]), tag), k + size
        return None

    def link_at(self, s, i):
        """Parse a link starting at s[i] == '['. Returns (text, href, title, end) or None."""
        n = len(s)
        depth = 0
        j = i
        while j < n:
            ch = s[j]
            if ch == "\\":
                j += 2
                continue
            if ch == "`":
                k = j
                while k < n and s[k] == "`":
                    k += 1
                close = s.find(s[j:k], k)
                j = (close + (k - j)) if close >= 0 else k
                continue
            if ch == "[":
                depth += 1
            elif ch == "]":
                depth -= 1
                if depth == 0:
                    break
            j += 1
        if j >= n:
            return None
        text = s[i + 1:j]
        k = j + 1
        if k < n and s[k] == "(":
            k += 1
            while k < n and s[k] in " \t\n":
                k += 1
            if k < n and s[k] == "<":
                e = s.find(">", k)
                if e < 0:
                    return None
                href = s[k + 1:e]
                k = e + 1
            else:
                start = k
                par = 0
                while k < n and not s[k].isspace():
                    if s[k] == "(":
                        par += 1
                    elif s[k] == ")":
                        if par == 0:
                            break
                        par -= 1
                    k += 1
                href = s[start:k]
            while k < n and s[k] in " \t\n":
                k += 1
            title = None
            if k < n and s[k] in "\"'(":
                close = {"\"": "\"", "'": "'", "(": ")"}[s[k]]
                e = s.find(close, k + 1)
                if e < 0:
                    return None
                title = s[k + 1:e]
                k = e + 1
                while k < n and s[k] in " \t\n":
                    k += 1
            if k >= n or s[k] != ")":
                return None
            return text, href, title, k + 1
        # reference links: [text][id], [text][], [text]
        if k < n and s[k] == "[":
            e = s.find("]", k)
            if e >= 0:
                ref = s[k + 1:e].strip() or text
                d = self.refs.get(norm_ref(ref))
                if d:
                    return text, d[0], d[1], e + 1
            return None
        d = self.refs.get(norm_ref(text))
        if d:
            return text, d[0], d[1], j + 1
        return None

    # ---- blocks -------------------------------------------------------------

    def heading_id(self, text_html):
        base = slugify(strip_tags(text_html)) or "section"
        count = self.ids.get(base, 0)
        self.ids[base] = count + 1
        return base if count == 0 else "%s-%d" % (base, count)

    def blocks(self, lines, top=False):
        out = []
        i = 0
        n = len(lines)
        pending_example = None
        while i < n:
            line = lines[i]
            stripped = line.strip()
            if not stripped:
                i += 1
                continue
            m = MARKER_RE.match(line)
            if m:
                pending_example = m.group(1)
                i += 1
                continue
            if stripped.startswith("<!--"):
                # an HTML comment block: dropped
                j = i
                while j < n and "-->" not in lines[j]:
                    j += 1
                i = j + 1
                continue
            example, pending_example = pending_example, None
            fm = FENCE_RE.match(line)
            if fm:
                indent, fence, info = len(fm.group(1)), fm.group(2), fm.group(3).strip()
                body = []
                i += 1
                while i < n:
                    cm = FENCE_RE.match(lines[i])
                    if cm and cm.group(2)[0] == fence[0] and len(cm.group(2)) >= len(fence) and not cm.group(3).strip():
                        break
                    l = lines[i]
                    k = 0
                    while k < indent and k < len(l) and l[k] == " ":
                        k += 1
                    body.append(l[k:])
                    i += 1
                i += 1
                out.append(self.code_block("\n".join(body), info.split()[0] if info else "", example))
                continue
            hm = HEADING_RE.match(line)
            if hm:
                level = len(hm.group(1))
                h = self.inline(hm.group(2) or "")
                hid = self.heading_id(h)
                self.headings.append((level, hid, h))
                anchor = '<a class="anchor" href="#%s" aria-hidden="true" tabindex="-1"></a>' % hid if level > 1 else ""
                out.append('<h%d id="%s">%s%s</h%d>' % (level, hid, h, anchor, level))
                i += 1
                continue
            if HR_RE.match(line):
                out.append("<hr>")
                i += 1
                continue
            if line.lstrip().startswith(">"):
                body = []
                while i < n and lines[i].strip():
                    l = lines[i].lstrip()
                    if l.startswith(">"):
                        l = l[1:]
                        if l.startswith(" "):
                            l = l[1:]
                    elif FENCE_RE.match(lines[i]) or HEADING_RE.match(lines[i]) or LIST_RE.match(lines[i]):
                        break
                    body.append(l)
                    i += 1
                out.append(self.blockquote(body))
                continue
            if LIST_RE.match(line):
                html_, i = self.list_block(lines, i)
                out.append(html_)
                continue
            if "|" in line and i + 1 < n and TABLE_SEP_RE.match(lines[i + 1]) and "-" in lines[i + 1]:
                html_, i = self.table(lines, i)
                out.append(html_)
                continue
            if HTML_BLOCK_RE.match(line):
                body = []
                while i < n and lines[i].strip():
                    body.append(lines[i])
                    i += 1
                out.append("\n".join(body))
                continue
            # paragraph
            body = []
            while i < n and lines[i].strip():
                l = lines[i]
                if body and (FENCE_RE.match(l) or HEADING_RE.match(l) or HR_RE.match(l) or l.lstrip().startswith(">")
                             or (LIST_RE.match(l) and LIST_RE.match(l).group(4).strip()) or HTML_BLOCK_RE.match(l)
                             or MARKER_RE.match(l) or l.strip().startswith("<!--")):
                    break
                body.append(l.strip() if not l.endswith("  ") else l.lstrip())
                i += 1
            out.append("<p>%s</p>" % self.inline("\n".join(body)).strip())
        return "\n".join(out)

    def code_block(self, code, lang, example=None):
        lang = re.sub(r"[^\w+-]", "", lang.lower())
        cls = ' class="language-%s"' % lang if lang else ""
        attrs = ' id="example-%s" data-example="%s"' % (esc(slugify(example)), esc(example)) if example else ""
        label = esc(lang or "text")
        if example:
            label += ' <span class="ex">example: %s</span>' % esc(example)
        return ('<div class="codeblock"%s><div class="code-head"><span>%s</span>'
                '<button class="copy" type="button">Copy</button></div>'
                '<pre><code%s>%s</code></pre></div>' % (attrs, label, cls, esc(code)))

    def blockquote(self, body):
        cls = ""
        title = ""
        if body:
            am = re.match(r"^\[!(\w+)\]\s*$", body[0].strip())
            if am and am.group(1).upper() in ALERTS:
                kind = am.group(1).upper()
                cls = ' class="alert alert-%s"' % kind.lower()
                title = '<p class="alert-title">%s</p>\n' % ALERTS[kind]
                body = body[1:]
        inner = Renderer(self.link_hook, self.refs)
        inner.ids = self.ids
        h = inner.blocks(body)
        self.headings.extend(inner.headings)
        return "<blockquote%s>\n%s%s\n</blockquote>" % (cls, title, h)

    def list_block(self, lines, i):
        n = len(lines)
        first = LIST_RE.match(lines[i])
        ordered = first.group(2)[0].isdigit()
        bullet = first.group(2)[-1]
        base_indent = len(first.group(1))
        items = []
        loose = False
        while i < n:
            m = LIST_RE.match(lines[i])
            if not m or len(m.group(1)) > base_indent + 1 or m.group(2)[-1] != bullet or m.group(2)[0].isdigit() != ordered:
                break
            content_indent = len(m.group(1)) + len(m.group(2)) + (len(m.group(3)) if m.group(4) else 1)
            if len(m.group(3)) > 4:
                content_indent = len(m.group(1)) + len(m.group(2)) + 1
            item = [m.group(4)]
            i += 1
            in_fence = bool(FENCE_RE.match(m.group(4)))
            while i < n:
                l = lines[i]
                if FENCE_RE.match(l.strip()) and (len(l) - len(l.lstrip()) >= content_indent or in_fence):
                    in_fence = not in_fence
                    item.append(l[content_indent:] if len(l) - len(l.lstrip()) >= content_indent else l.lstrip())
                    i += 1
                    continue
                if in_fence:
                    item.append(l[content_indent:] if l[:content_indent].strip() == "" else l)
                    i += 1
                    continue
                if not l.strip():
                    # blank: the item continues if the next non-blank line is indented
                    j = i
                    while j < n and not lines[j].strip():
                        j += 1
                    if j < n and len(lines[j]) - len(lines[j].lstrip()) >= content_indent:
                        item.extend([""] * (j - i))
                        i = j
                        loose = True
                        continue
                    if j < n and LIST_RE.match(lines[j]) and len(LIST_RE.match(lines[j]).group(1)) <= base_indent + 1:
                        nm = LIST_RE.match(lines[j])
                        if nm.group(2)[-1] == bullet and nm.group(2)[0].isdigit() == ordered:
                            loose = True
                    break
                ind = len(l) - len(l.lstrip())
                if ind >= content_indent:
                    item.append(l[content_indent:])
                    i += 1
                    continue
                if LIST_RE.match(l) or HEADING_RE.match(l) or FENCE_RE.match(l) or HR_RE.match(l) or l.lstrip().startswith(">"):
                    break
                # lazy continuation of the item's paragraph
                item.append(l.strip())
                i += 1
            items.append(item)
        lis = []
        for item in items:
            inner = Renderer(self.link_hook, self.refs)
            inner.ids = self.ids
            h = inner.blocks(item)
            self.headings.extend(inner.headings)
            if not loose:
                h = re.sub(r"^<p>(.*?)</p>", r"\1", h, count=1, flags=re.S)
            lis.append("<li>%s</li>" % h)
        if ordered:
            start = int(first.group(2)[:-1])
            tag = "<ol%s>" % (' start="%d"' % start if start != 1 else "")
            return "%s\n%s\n</ol>" % (tag, "\n".join(lis)), i
        return "<ul>\n%s\n</ul>" % "\n".join(lis), i

    def table(self, lines, i):
        def cells(line):
            s = line.strip()
            if s.startswith("|"):
                s = s[1:]
            if s.endswith("|") and not s.endswith("\\|"):
                s = s[:-1]
            parts, cur, k = [], [], 0
            while k < len(s):
                if s[k] == "\\" and k + 1 < len(s) and s[k + 1] == "|":
                    cur.append("|")
                    k += 2
                    continue
                if s[k] == "|":
                    parts.append("".join(cur).strip())
                    cur = []
                else:
                    cur.append(s[k])
                k += 1
            parts.append("".join(cur).strip())
            return parts

        head = cells(lines[i])
        aligns = []
        for c in cells(lines[i + 1]):
            c = c.strip()
            aligns.append("center" if c.startswith(":") and c.endswith(":") else "right" if c.endswith(":") else "left" if c.startswith(":") else None)
        i += 2
        rows = []
        while i < len(lines) and lines[i].strip() and "|" in lines[i]:
            rows.append(cells(lines[i]))
            i += 1

        def cell(tag, text, k):
            a = aligns[k] if k < len(aligns) else None
            st = ' style="text-align:%s"' % a if a else ""
            return "<%s%s>%s</%s>" % (tag, st, self.inline(text), tag)

        width = len(head)
        h = ["<div class=\"table\"><table>", "<thead><tr>%s</tr></thead>" % "".join(cell("th", c, k) for k, c in enumerate(head)), "<tbody>"]
        for r in rows:
            r = (r + [""] * width)[:width]
            h.append("<tr>%s</tr>" % "".join(cell("td", c, k) for k, c in enumerate(r)))
        h.append("</tbody></table></div>")
        return "\n".join(h), i


def norm_ref(s):
    return " ".join(s.lower().split())


REFDEF_RE = re.compile(r"^ {0,3}\[([^\]]+)\]:\s*<?([^\s>]+)>?(?:\s+[\"'(](.*)[\"')])?\s*$")


def split_refs(lines):
    """Remove reference definitions (outside code) and return (lines, refs)."""
    out, refs = [], {}
    fence = None
    for l in lines:
        fm = FENCE_RE.match(l)
        if fence is None and fm:
            fence = fm.group(2)
        elif fence is not None and fm and fm.group(2)[0] == fence[0] and len(fm.group(2)) >= len(fence) and not fm.group(3).strip():
            fence = None
        elif fence is None:
            m = REFDEF_RE.match(l)
            if m:
                refs.setdefault(norm_ref(m.group(1)), (m.group(2), m.group(3)))
                continue
        out.append(l)
    return out, refs


def prose_lines(lines):
    """Lines with fenced code blanked out."""
    out = []
    fence = None
    for l in lines:
        fm = FENCE_RE.match(l)
        if fence is None and fm:
            fence = fm.group(2)
            out.append("")
        elif fence is not None:
            if fm and fm.group(2)[0] == fence[0] and len(fm.group(2)) >= len(fence) and not fm.group(3).strip():
                fence = None
            out.append("")
        else:
            out.append(l)
    return out


# ---------------------------------------------------------------------------
# Pages
# ---------------------------------------------------------------------------

def plain_inline(md):
    """Markdown inline text to plain text."""
    r = Renderer(lambda h: h)
    return " ".join(strip_tags(r.inline(md)).split())


class Page:
    def __init__(self, rel, text):
        self.rel = rel  # path relative to the docs dir, with '/'
        self.text = text
        d, base = os.path.split(rel)
        self.dir = d
        stem = base[:-3]
        self.stem = stem
        self.out = (d + "/" if d else "") + ("index.html" if stem.lower() == "readme" else stem + ".html")
        self.section = d.split("/")[0] if d else ""
        lines = text.split("\n")
        prose = prose_lines(lines)
        self.title = stem
        self.answer = ""
        self.fields = {}
        self.faq = []
        m = re.search(r"<!--\s*canonical:\s*(\S+)\s*-->", text)
        self.canonical = m.group(1) if m else None
        title_line = None
        for k, l in enumerate(prose):
            m = HEADING_RE.match(l)
            if m and len(m.group(1)) == 1:
                self.title = plain_inline(m.group(2) or stem)
                title_line = k
                break
        start = (title_line + 1) if title_line is not None else 0
        # the answer: the first blockquote after the H1 (before any other heading)
        k = start
        while k < len(prose) and not prose[k].strip():
            k += 1
        if k < len(prose) and prose[k].lstrip().startswith(">"):
            q = []
            while k < len(prose) and prose[k].strip():
                q.append(re.sub(r"^\s*>\s?", "", prose[k]))
                k += 1
            self.answer = plain_inline(" ".join(q))
        if not self.answer:
            for l in prose[start:]:
                s = l.strip()
                if s and not s.startswith(("#", "|", "<", "-", "*", ">", "!")) and not re.match(r"\d+\.", s):
                    self.answer = plain_inline(s)
                    break
        # **Field:** value · **Field:** value lines
        for l in prose[start:start + 12]:
            for fm in re.finditer(r"\*\*([A-Za-z ]+):\*\*\s*(.*?)(?=\s*(?:·\s*)?\*\*[A-Za-z ]+:\*\*|$)", l):
                self.fields.setdefault(fm.group(1).strip().lower(), fm.group(2).strip().rstrip("·").strip())
        self.also = [a.rstrip(":").rstrip("/").rstrip(":") for a in re.findall(r"`([^`]+)`", self.fields.get("also", ""))]
        self.schemes = [a.rstrip(":").rstrip("/").rstrip(":") for a in re.findall(r"`([^`]+)`", self.fields.get("scheme", ""))]
        # FAQ: "## Common questions" -> "### question" + answer text
        in_faq = False
        q, a = None, []
        for l in prose[start:]:
            m = HEADING_RE.match(l)
            if m and len(m.group(1)) == 2:
                if in_faq and q:
                    self.faq.append((q, a))
                    q, a = None, []
                in_faq = (m.group(2) or "").strip().lower().rstrip("?") in ("common questions", "faq", "frequently asked questions")
                continue
            if not in_faq:
                continue
            if m and len(m.group(1)) == 3:
                if q:
                    self.faq.append((q, a))
                q, a = plain_inline(m.group(2) or ""), []
            elif q is not None and not l.strip().startswith("<!--"):
                a.append(l)
        if in_faq and q:
            self.faq.append((q, a))
        self.faq = [(q, plain_inline(" ".join(x.strip() for x in a if x.strip()))) for q, a in self.faq]
        self.faq = [(q, a) for q, a in self.faq if q and a]
        self.category = category_for(stem, self.fields.get("category")) if self.section == "components" else None


def pack_kind(p):
    """For a page under packs/<pack>/<kind>/: the kind (components, dataformats, ...), else ''."""
    parts = p.dir.split("/")
    return parts[2] if p.section == "packs" and len(parts) > 2 else ""


def nav_title(p):
    t = p.title
    kind = pack_kind(p) or p.section
    if kind == "components":
        t = re.sub(r"\s+component$", "", t, flags=re.I)
    elif kind == "languages":
        t = re.sub(r"\s+language$", "", t, flags=re.I)
    elif kind == "dataformats":
        t = re.sub(r"\s+data format$", "", t, flags=re.I)
    return t


def abs_url(out):
    """Absolute URL of an output page; index pages get the directory URL."""
    if out == "index.html" or out.endswith("/index.html"):
        out = out[:-len("index.html")]
    return SITE_URL + "docs/" + out


def relurl(from_out, to_out):
    """Relative URL from one output page to another (both relative to the docs root)."""
    fd = os.path.dirname(from_out)
    r = os.path.relpath(to_out, fd or ".").replace("\\", "/")
    return r


class Site:
    def __init__(self, repo, docs, out):
        self.repo = repo
        self.docs = docs
        self.out = out
        self.pages = {}  # rel md -> Page
        self.assets = []  # rel paths of non-md files
        self.errors = []
        self.dates = {}
        self.anchor_checks = []  # (from page rel, target out, anchor)
        self.generated = {}  # out -> title (generated index pages)

    def load(self):
        for root, dirs, files in os.walk(self.docs):
            # the Read the Docs (Sphinx) build output is not part of the website
            dirs[:] = sorted(d for d in dirs if d != "_build" and not (root == self.docs and d in INTERNAL_DIRS))
            for f in sorted(files):
                full = os.path.join(root, f)
                rel = os.path.relpath(full, self.docs).replace("\\", "/")
                if rel in SPHINX_ONLY or rel in INTERNAL:
                    continue
                if f.lower().endswith(".md"):
                    with open(full, encoding="utf-8") as fh:
                        self.pages[rel] = Page(rel, fh.read().replace("\r\n", "\n"))
                else:
                    self.assets.append(rel)
        outs = {}
        for p in self.pages.values():
            if p.out in outs:
                raise BuildError("%s and %s both render to %s" % (outs[p.out], p.rel, p.out))
            outs[p.out] = p.rel
        self.by_out = {p.out: p for p in self.pages.values()}
        if "index.html" not in self.by_out:
            self.generated["index.html"] = "simoom documentation"
        for d, _, title, _ in SECTIONS:
            if d + "/index.html" not in self.by_out:
                self.generated[d + "/index.html"] = title
        self.git_dates()

    def git_dates(self):
        """Last commit date (YYYY-MM-DD) of every file under the docs dir, in one git call."""
        try:
            r = subprocess.run(["git", "log", "--format=@%cs", "--name-only", "--", "."], cwd=self.docs,
                               capture_output=True, text=True, timeout=60)
            top = subprocess.run(["git", "rev-parse", "--show-prefix"], cwd=self.docs, capture_output=True, text=True, timeout=10)
        except (OSError, subprocess.SubprocessError):
            return
        if r.returncode != 0 or top.returncode != 0:
            return
        prefix = top.stdout.strip()
        date = None
        for line in r.stdout.splitlines():
            if line.startswith("@"):
                date = line[1:]
            elif line.strip() and date:
                path = line.strip()
                if path.startswith(prefix):
                    self.dates.setdefault(path[len(prefix):], date)

    def date_of(self, out):
        cache = self.__dict__.setdefault("cache_dates", {})
        if out not in cache:
            cache[out] = self._date_of(out)
        return cache[out]

    def _date_of(self, out):
        p = self.by_out.get(out)
        if p:
            return self.dates.get(p.rel)
        # generated pages: the newest page in their section
        sec = out.split("/")[0] if "/" in out else ""
        ds = [self.dates[q.rel] for q in self.pages.values() if q.rel in self.dates and (not sec or q.section == sec)]
        if not ds:
            ds = list(self.dates.values())
        return max(ds) if ds else None

    # ---- links --------------------------------------------------------------

    def link_hook_for(self, page_out, page_dir, label):
        def hook(href):
            href = href.strip()
            if not href or href.startswith("#"):
                if href.startswith("#") and len(href) > 1:
                    self.anchor_checks.append((label, page_out, href[1:]))
                return href
            if re.match(r"^[A-Za-z][A-Za-z0-9+.-]*:", href) or href.startswith("//"):
                return href
            path, _, frag = href.partition("#")
            path, _, query = path.partition("?")
            target = os.path.normpath(os.path.join(self.docs, page_dir, path.replace("%20", " ")))
            reldocs = os.path.relpath(target, self.docs).replace("\\", "/")
            if reldocs.startswith(".."):
                # outside docs/: link to the file on GitHub (the docs dir's parent is the repo root)
                relrepo = os.path.relpath(target, os.path.dirname(self.docs)).replace("\\", "/")
                if relrepo.startswith("..") or not os.path.exists(target):
                    self.errors.append("%s: link `%s` points outside the repository or to a missing file" % (label, href))
                    return href
                kind = "tree" if os.path.isdir(target) else "blob"
                return "%s/%s/main/%s%s" % (REPO_URL, kind, relrepo, "#" + frag if frag else "")
            if reldocs == ".":
                reldocs = ""
            out = None
            if reldocs.endswith(".md") and reldocs in self.pages:
                out = self.pages[reldocs].out
            elif (reldocs + "/index.html").lstrip("/") in self.by_out or (reldocs + "/index.html").lstrip("/") in self.generated:
                out = (reldocs + "/index.html").lstrip("/")
            elif reldocs in self.assets:
                return relurl(page_out, reldocs) + ("#" + frag if frag else "")
            if out is None:
                self.errors.append("%s: broken link `%s`" % (label, href))
                return href
            if frag:
                self.anchor_checks.append((label, out, frag))
            return relurl(page_out, out) + ("#" + frag if frag else "")
        return hook

    # ---- output -------------------------------------------------------------

    def ordered(self, section):
        cache = self.__dict__.setdefault("cache_ordered", {})
        if section not in cache:
            cache[section] = self._ordered(section)
        return cache[section]

    def _ordered(self, section):
        ps = [p for p in self.pages.values() if p.section == section and p.out != section + "/index.html"]
        if section == "guides":
            def key(p):
                name = p.out[len("guides/"):-len(".html")] if p.out.startswith("guides/") else p.stem
                return (GUIDE_ORDER.index(name) if name in GUIDE_ORDER else len(GUIDE_ORDER), p.title.lower())
        else:
            def key(p):
                return nav_title(p).lower()
        return sorted(ps, key=key)

    def project_pages(self):
        return sorted([p for p in self.pages.values() if not p.dir and p.out != "index.html"], key=lambda p: p.title.lower())

    def other_pages(self):
        return sorted([p for p in self.pages.values() if p.dir and p.section not in SECTION_DIRS and p.section != "packs"
                       and not p.out.endswith("index.html")], key=lambda p: p.rel)

    def pack_nav(self, cur, link):
        """The Packs group of the navigation: the packs index, then each pack with its pages."""
        pages = [p for p in self.pages.values() if p.section == "packs"]
        if not pages:
            return ""
        kinds = ["guides", "components", "dataformats", "languages", "conformance"]
        body = [link("packs/index.html", "All packs")] if "packs/index.html" in self.by_out else []
        packs = sorted(set(p.dir.split("/")[1] for p in pages if "/" in p.dir))
        for name in packs:
            home = "packs/%s/index.html" % name
            own = [p for p in pages if (p.dir + "/").startswith("packs/%s/" % name) and p.out != home]
            own.sort(key=lambda p: (kinds.index(pack_kind(p)) if pack_kind(p) in kinds else len(kinds), nav_title(p).lower()))
            title = self.by_out[home].title if home in self.by_out else name
            items = ([link(home, "Overview")] if home in self.by_out else []) + [link(p.out, p.title) for p in own]
            open_pack = cur.startswith("packs/%s/" % name)
            body.append('<li><details%s><summary>%s <span class="n">%d</span></summary><ul>%s</ul></details></li>'
                        % (" open" if open_pack else "", esc(title), len(own), "".join(items)))
        is_open = cur.startswith("packs/")
        return ('<details class="nav-group"%s><summary>Packs <span class="n">%d</span></summary><ul>%s</ul></details>'
                % (" open" if is_open else "", len(pages), "".join(body)))

    def all_outs(self):
        outs = set(self.by_out) | set(self.generated)
        return sorted(outs)

    def nav(self, cur):
        """The left navigation, relative to page `cur` (an output path)."""
        cur_section = cur.split("/")[0] if "/" in cur else ""
        cur_page = self.by_out.get(cur)

        def link(out, title):
            a = ' aria-current="page"' if out == cur else ""
            return '<li><a href="%s"%s>%s</a></li>' % (esc(relurl(cur, out)), a, esc(title))

        h = ['<ul class="nav-top">', link("index.html", "Docs home"), "</ul>"]
        for d, title, _, _ in SECTIONS:
            pages = self.ordered(d)
            is_open = cur_section == d
            body = [link(d + "/index.html", "All " + title.lower() if d != "guides" else "All guides")]
            if d == "components":
                cats = {}
                for p in pages:
                    cats.setdefault(p.category, []).append(p)
                for cat in sorted(cats, key=lambda c: (CATEGORY_ORDER.index(c) if c in CATEGORY_ORDER else len(CATEGORY_ORDER), c)):
                    open_cat = cur_page is not None and cur_page.section == "components" and cur_page.category == cat
                    items = "".join(link(p.out, nav_title(p)) for p in cats[cat])
                    body.append('<li><details%s><summary>%s <span class="n">%d</span></summary><ul>%s</ul></details></li>'
                                % (" open" if open_cat else "", esc(cat), len(cats[cat]), items))
            else:
                body.extend(link(p.out, nav_title(p)) for p in pages)
            h.append('<details class="nav-group"%s><summary>%s <span class="n">%d</span></summary><ul>%s</ul></details>'
                     % (" open" if is_open else "", esc(title), len(pages), "".join(body)))
        packs = self.pack_nav(cur, link)
        if packs:
            h.append(packs)
        proj = self.project_pages() + self.other_pages()
        if proj:
            is_open = cur_page is not None and (not cur_page.dir or cur_page.section not in SECTION_DIRS + ["packs"]) and cur != "index.html"
            h.append('<details class="nav-group"%s><summary>Project <span class="n">%d</span></summary><ul>%s</ul></details>'
                     % (" open" if is_open else "", len(proj), "".join(link(p.out, p.title) for p in proj)))
        return "\n".join(h)

    def breadcrumbs(self, out, title):
        crumbs = [("Docs", "index.html")]
        sec = out.split("/")[0] if "/" in out else ""
        if sec:
            st = dict([(s[0], s[1]) for s in SECTIONS] + [("packs", "Packs")]).get(sec, sec)
            if out != sec + "/index.html":
                crumbs.append((st, sec + "/index.html" if (sec + "/index.html") in self.generated or (sec + "/index.html") in self.by_out else None))
        if out != "index.html":
            crumbs.append((title, out))
        return crumbs

    def page_html(self, out, title, answer, body, headings, faq, source_rel=None, canonical=None):
        url = canonical or abs_url(out)
        root = relurl(out, "index.html")[:-len("index.html")]  # '' or '../'
        site_root = root + "../"
        host_root = site_root + "../"  # the main site (cameleer.ing/)
        desc = answer or "%s: simoom documentation." % title
        crumbs = self.breadcrumbs(out, title)
        date = self.date_of(out)
        ld = [{
            "@context": "https://schema.org",
            "@type": "TechArticle",
            "headline": title,
            "description": desc,
            "url": url,
            "inLanguage": "en",
            "author": {"@type": "Person", "name": "Sudheesh PM"},
            "publisher": {"@id": "https://cameleer.ing/#org"},  # the Cameleering Organization, defined at the root
            "isPartOf": {"@type": "WebSite", "name": SITE_NAME + " documentation", "url": SITE_URL + "docs/"},
            "about": {"@type": "SoftwareSourceCode", "name": SITE_NAME, "codeRepository": REPO_URL, "programmingLanguage": "Rust"},
            "image": SITE_URL + "og.jpg",
        }]
        if date:
            ld[0]["dateModified"] = date
        # structured-data trail starts at the practice home, then simoom, then the docs crumbs
        items = [{"@type": "ListItem", "position": 1, "name": "Cameleering", "item": "https://cameleer.ing/"},
                 {"@type": "ListItem", "position": 2, "name": SITE_NAME, "item": SITE_URL}]
        for k, (name, o) in enumerate(crumbs, start=2):
            it = {"@type": "ListItem", "position": k + 1, "name": name}
            if o:
                it["item"] = abs_url(o)
            items.append(it)
        ld.append({"@context": "https://schema.org", "@type": "BreadcrumbList", "itemListElement": items})
        if faq:
            ld.append({"@context": "https://schema.org", "@type": "FAQPage", "mainEntity": [
                {"@type": "Question", "name": q, "acceptedAnswer": {"@type": "Answer", "text": a}} for q, a in faq]})
        ld_json = "\n".join('<script type="application/ld+json">%s</script>' % json.dumps(x, ensure_ascii=False, sort_keys=False).replace("</", "<\\/") for x in ld)

        crumb_html = " <span aria-hidden=\"true\">/</span> ".join(
            ('<a href="%s">%s</a>' % (esc(relurl(out, o)), esc(n)) if o and o != out else '<span>%s</span>' % esc(n)) for n, o in crumbs)
        toc = ""
        h2 = [(i, h) for (lvl, i, h) in headings if lvl == 2]
        if len(h2) >= 3:
            toc = '<nav class="toc" aria-label="On this page"><p>On this page</p><ul>%s</ul></nav>' % "".join(
                '<li><a href="#%s">%s</a></li>' % (i, strip_tags_keep_code(h)) for i, h in h2)
        edit = ""
        alt = ""
        if source_rel:
            edit = '<p class="edit"><a href="%s/blob/main/docs/%s">Edit this page on GitHub</a></p>' % (REPO_URL, esc(source_rel))
            alt = '<link rel="alternate" type="text/markdown" href="%s" title="Markdown source">\n' % esc(os.path.basename(source_rel))
        return TEMPLATE.format(
            title=esc(title), full_title=esc("%s | %s" % (title, SITE_NAME) if title != SITE_NAME else SITE_NAME),
            desc=esc(desc), url=esc(url), root=root, site_root=site_root, host_root=host_root, ld=ld_json, alt=alt,
            nav=self.nav(out), crumbs=crumb_html, body=body, toc=toc, edit=edit,
            og_image=SITE_URL + "og.jpg",
        )

    def render_page(self, p):
        lines, refs = split_refs(p.text.split("\n"))
        r = Renderer(self.link_hook_for(p.out, p.dir, p.rel), refs)
        body = r.blocks(lines, top=True)
        # mark the answer blockquote
        body = re.sub(r"(</h1>\s*)<blockquote>", r'\1<blockquote class="answer">', body, count=1)
        self.ids_by_out[p.out] = set(re.findall(r' id="([^"]+)"', body))
        return self.page_html(p.out, p.title, p.answer, body, r.headings, p.faq, p.rel, p.canonical)

    def index_table(self, out, pages, with_category):
        rows = []
        groups = []
        if with_category:
            cats = {}
            for p in pages:
                cats.setdefault(p.category, []).append(p)
            for cat in sorted(cats, key=lambda c: (CATEGORY_ORDER.index(c) if c in CATEGORY_ORDER else len(CATEGORY_ORDER), c)):
                groups.append((cat, cats[cat]))
        else:
            groups.append((None, pages))
        h = ['<div class="filter"><label for="filter">Filter</label>'
             '<input id="filter" type="search" placeholder="Type a name, scheme or use case" autocomplete="off">'
             '<span class="count" aria-live="polite"></span></div>',
             '<div class="table"><table class="index-table"><thead><tr><th>Name</th>%s<th>What it does</th></tr></thead>'
             % ("<th>Scheme</th>" if with_category else "")]
        for cat, ps in groups:
            h.append("<tbody>")
            if cat:
                h.append('<tr class="cat"><th colspan="3" id="%s">%s <span class="n">%d</span></th></tr>' % (slugify(cat), esc(cat), len(ps)))
            for p in ps:
                schemes = ", ".join("<code>%s</code>" % esc(s) for s in (p.schemes or [p.stem]) + p.also)
                rows.append(p)
                h.append('<tr%s><td><a href="%s">%s</a></td>%s<td>%s</td></tr>' % (
                    ' data-cat="%s"' % esc(cat) if cat else "", esc(relurl(out, p.out)), esc(nav_title(p)), "<td>%s</td>" % schemes if with_category else "", esc(p.answer)))
            h.append("</tbody>")
        h.append("</table></div>")
        if not pages:
            h = ["<p>No pages yet.</p>"]
        return "\n".join(h)

    def render_generated(self, out):
        if out == "index.html":
            title = "simoom documentation"
            answer = "Documentation for simoom, the small, fast HTTP server engine you build into Rust programs: guides, security and FAQ."
            parts = []
            for d, t, _, a in SECTIONS:
                parts.append('<h2 id="%s"><a href="%s">%s</a></h2><p>%s</p>' % (d, d + "/index.html", esc(t), esc(a)))
            body = "<h1>%s</h1>\n<blockquote class=\"answer\"><p>%s</p></blockquote>\n%s" % (esc(title), esc(answer), "\n".join(parts))
            self.ids_by_out[out] = set(SECTION_DIRS)
            return self.page_html(out, title, answer, body, [], [])
        d = out.split("/")[0]
        sec = [s for s in SECTIONS if s[0] == d][0]
        title, answer = sec[2], sec[3]
        pages = self.ordered(d)
        if d == "guides":
            items = "".join('<li><a href="%s">%s</a> <span class="muted">%s</span></li>' % (esc(relurl(out, p.out)), esc(p.title), esc(p.answer)) for p in pages)
            listing = '<ul class="guide-list">%s</ul>' % items if pages else "<p>No guides yet.</p>"
        else:
            listing = self.index_table(out, pages, d == "components")
        body = '<h1>%s</h1>\n<blockquote class="answer"><p>%s</p></blockquote>\n%s' % (esc(title), esc(answer), listing)
        ids = {"filter"}
        if d == "components":
            ids |= {slugify(p.category) for p in pages}
        self.ids_by_out[out] = ids
        return self.page_html(out, title, answer, body, [], [])

    def build(self):
        t0 = time.time()
        self.load()
        docs_out = os.path.join(self.out, "docs")
        rendered = {}
        self.ids_by_out = {}
        for p in sorted(self.pages.values(), key=lambda p: p.rel):
            rendered[p.out] = self.render_page(p)
        for out in sorted(self.generated):
            rendered[out] = self.render_generated(out)
        for label, out, frag in self.anchor_checks:
            ids = self.ids_by_out.get(out)
            if ids is not None and frag not in ids:
                self.errors.append("%s: anchor `#%s` not found in %s" % (label, frag, out))
        if self.errors:
            raise BuildError("broken internal links (%d):\n  %s" % (len(self.errors), "\n  ".join(sorted(set(self.errors)))))
        if os.path.isdir(docs_out):
            shutil.rmtree(docs_out)
        for out, h in rendered.items():
            write(os.path.join(docs_out, out), h)
        for p in self.pages.values():
            write(os.path.join(docs_out, p.rel), p.text)
        for a in self.assets:
            dst = os.path.join(docs_out, a)
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            shutil.copyfile(os.path.join(self.docs, a), dst)
        self.write_moved(docs_out)
        self.write_sitemap()
        self.write_llms()
        return len(rendered), time.time() - t0

    # ---- sitemap and llms ---------------------------------------------------

    def write_sitemap(self):
        home_date = max([d for d in self.dates.values()] or [""]) or None
        urls = [(SITE_URL, home_date), (SITE_URL + "llms.txt", home_date), (SITE_URL + "llms-full.txt", home_date)]
        for rel in self.designed_pages():
            urls.append((SITE_URL + rel[: -len("index.html")], self.git_date(os.path.join(self.out, rel)) or home_date))
        for out in self.all_outs():
            p = self.by_out.get(out)
            if p is not None and p.canonical:
                continue
            urls.append((abs_url(out), self.date_of(out)))
        lines = ['<?xml version="1.0" encoding="UTF-8"?>', '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">']
        for u, d in urls:
            lines.append("  <url><loc>%s</loc>%s</url>" % (esc(u), "<lastmod>%s</lastmod>" % d if d else ""))
        lines.append("</urlset>")
        write(os.path.join(self.out, "sitemap.xml"), "\n".join(lines) + "\n")

    def designed_pages(self):
        """Hand-written landing pages: <out>/use-cases/**, <out>/compare/**, <out>/alternatives/** and <out>/benchmarks/** (index.html)."""
        found = []
        for d, _, files in (w for top in ("use-cases", "compare", "alternatives", "benchmarks") for w in os.walk(os.path.join(self.out, top))):
            if "index.html" in files:
                found.append(os.path.relpath(os.path.join(d, "index.html"), self.out).replace("\\", "/"))
        return sorted(found)

    def git_date(self, path):
        try:
            out = subprocess.run(["git", "log", "-1", "--format=%cs", "--", path], cwd=self.repo, capture_output=True, text=True, check=False).stdout.strip()
            return out or None
        except OSError:
            return None

    def abs_md(self, page, text):
        """Markdown text with relative links made absolute (for llms-full.txt)."""
        hook = self.link_hook_for(page.out, page.dir, page.rel)
        out = []
        for l, prose in zip(text.split("\n"), prose_lines(text.split("\n"))):
            if not prose.strip():
                out.append(l)
                continue
            if l.strip().startswith("<!--") and l.strip().endswith("-->"):
                continue

            def rep(m):
                href = m.group(2)
                if href.startswith("#") or re.match(r"^[A-Za-z][A-Za-z0-9+.-]*:", href):
                    return m.group(0)
                new = hook(href)
                if not re.match(r"^https?:", new):
                    new = SITE_URL + "docs/" + os.path.normpath(os.path.join(os.path.dirname(page.out), new)).replace("\\", "/")
                return m.group(1) + new + ")"
            out.append(re.sub(r"(\]\()([^)\s]+)\)", rep, l))
        return "\n".join(out)

    def write_moved(self, docs_out):
        """Pages that moved keep their old URL as a redirect, so links and search results still work."""
        for old, new in MOVED.items():
            if old in self.by_out:
                raise BuildError("%s is in MOVED but a page renders there" % old)
            if new not in self.by_out:
                raise BuildError("MOVED %s -> %s: no page renders to %s" % (old, new, new))
            rel = relurl(old, new)
            url = abs_url(new)
            title = self.by_out[new].title
            write(os.path.join(docs_out, old), (
                '<!doctype html>\n<html lang="en"><head><meta charset="utf-8">\n'
                '<title>%s (moved) | %s</title>\n'
                '<link rel="canonical" href="%s">\n<meta name="robots" content="noindex">\n'
                '<meta http-equiv="refresh" content="0; url=%s">\n</head>\n'
                '<body><p>This page moved to <a href="%s">%s</a>.</p></body></html>\n')
                % (esc(title), SITE_NAME, esc(url), esc(rel), esc(rel), esc(title)))

    def write_llms(self):
        u = abs_url
        sec = ["## Documentation", "",
               "The full documentation as one plain-markdown file: %sllms-full.txt. Every page is also served as markdown next to its HTML (same path, `.md`)." % SITE_URL, ""]
        sec.append("- [Docs home](%s): what is where" % u("index.html"))
        for d, t, _, a in SECTIONS:
            n = len(self.ordered(d))
            sec.append("- [%s](%s): %s (%d pages)" % (t, u(d + "/index.html"), a, n))
        packs = sorted((p for p in self.pages.values() if p.section == "packs"),
                       key=lambda p: (p.out.count("/"), p.out))
        if packs:
            sec.append("")
            sec.append("Packs (optional, not in the default build or image):")
            sec.append("")
            for p in packs:
                sec.append("- [%s](%s): %s" % (p.title, u(p.out), p.answer))
        guides = self.ordered("guides")
        if guides:
            sec.append("")
            sec.append("Guides:")
            sec.append("")
            for p in guides:
                sec.append("- [%s](%s): %s" % (p.title, u(p.out), p.answer))
        block = "\n".join(sec) + "\n"
        src = os.path.join(self.out, "llms.txt")
        base = open(src, encoding="utf-8").read() if os.path.exists(src) else "# simoom\n"
        base = base.replace("\r\n", "\n")
        # replace an existing generated section, else insert it before "## Docs" (or append)
        m = re.search(r"^## Documentation\n.*?(?=^## |\Z)", base, flags=re.M | re.S)
        if m:
            text = base[:m.start()] + block + "\n" + base[m.end():].lstrip("\n")
        else:
            k = base.find("\n## Docs\n")
            text = base[:k + 1] + block + "\n" + base[k + 1:] if k >= 0 else base.rstrip("\n") + "\n\n" + block
        write(os.path.join(self.out, "llms.txt"), text.rstrip("\n") + "\n")

        full = ["# simoom documentation (full text)", "",
                "> Every page of the simoom documentation (%sdocs/) concatenated as plain markdown, for LLMs and coding assistants. simoom is a small, fast HTTP/1.1, HTTP/2 and HTTP/3 server engine you build into Rust programs, with its own TLS 1.3 and nothing but the Rust standard library underneath." % SITE_URL, ""]
        order = []
        if "index.html" in self.by_out:
            order.append(self.by_out["index.html"])
        for d in SECTION_DIRS:
            if d + "/index.html" in self.by_out:
                order.append(self.by_out[d + "/index.html"])
            order.extend(self.ordered(d))
        order.extend(self.project_pages())
        order.extend(self.other_pages())
        for p in order:
            full.append("---")
            full.append("")
            full.append("Source: %s" % u(p.out))
            full.append("")
            full.append(self.abs_md(p, p.text).strip("\n"))
            full.append("")
        write(os.path.join(self.out, "llms-full.txt"), "\n".join(full))


def strip_tags_keep_code(h):
    return re.sub(r"<(?!/?code\b)[^>]+>", "", re.sub(r'<a class="anchor".*?</a>', "", h))


def write(path, text):
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write(text)


TEMPLATE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{full_title}</title>
<meta name="description" content="{desc}">
<link rel="canonical" href="{url}">
<meta name="theme-color" content="#ffffff">
<meta property="og:type" content="article">
<meta property="og:site_name" content="simoom">
<meta property="og:title" content="{title}">
<meta property="og:description" content="{desc}">
<meta property="og:url" content="{url}">
<meta property="og:image" content="{og_image}">
<meta name="twitter:card" content="summary_large_image">
<link rel="icon" href="{site_root}brand/simoom-mark.svg" type="image/svg+xml">
<link rel="icon" href="{host_root}favicon-32.png" sizes="32x32" type="image/png">
<link rel="apple-touch-icon" href="{host_root}apple-touch-icon.png">
<link rel="alternate" type="text/plain" href="{site_root}llms.txt" title="LLM-readable summary">
{alt}<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Schibsted+Grotesk:wght@400;500;700;800&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
<link rel="stylesheet" href="{host_root}assets/site.css">
{ld}
</head>
<body class="docs">
<a class="skip" href="#content">Skip to content</a>
<header class="top scrolled" id="top">
  <div class="wrap">
    <a class="brand" href="{site_root}" aria-label="simoom home">
      <img src="{site_root}brand/simoom-mark.svg" width="32" height="32" alt="" aria-hidden="true">
      simoom
    </a>
    <button class="nav-toggle" type="button" aria-expanded="false" aria-controls="main-nav" onclick="var t=this.closest('.top'),o=t.classList.toggle('open');this.setAttribute('aria-expanded',o)"><span class="bars" aria-hidden="true"></span>Menu</button>
    <nav id="main-nav" aria-label="Main">
      <a class="keep" href="{root}index.html">Docs</a>
      <a href="{root}guides/index.html">Guides</a>
      <a href="{site_root}use-cases/">Use cases</a>
      <a href="{site_root}benchmarks/">Benchmarks</a>
      <a href="{site_root}compare/">Compare</a>
      <!-- cameleering family menu v1 (keep in step with cameleer scripts/build-docs.py FAMILY_MENU) -->
      <div class="nav-menu">
        <a href="{host_root}" aria-haspopup="true">Cameleering</a>
        <div class="nav-sub">
          <a href="{host_root}"><b>Cameleering</b><span>Carry more on less, measured against the original</span></a>
          <a href="{host_root}ledger/"><b>The ledger</b><span>Every project, its baseline and its losses</span></a>
          <a href="{host_root}method/"><b>The method</b><span>How a gain is measured and reported</span></a>
          <a href="{host_root}finops/"><b>Code efficiency and FinOps</b><span>What the milliseconds and megabytes cost</span></a>
          <a href="{host_root}projects/"><b>Projects</b><span>Cameleer and simoom Cameleered; karez and ksar not yet</span></a>
          <a href="{host_root}about/"><b>About</b><span>Who maintains it, how to get in touch</span></a>
          <a href="{host_root}cameleer/"><b>Cameleer</b><span>The integration engine, in the style of Apache Camel</span></a>
        </div>
      </div>
      <a class="gh" href="https://github.com/Cameleering/simoom">
        <svg width="16" height="16" viewBox="0 0 16 16" aria-hidden="true"><path fill="currentColor" d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.013 8.013 0 0016 8c0-4.42-3.58-8-8-8z"/></svg>
        GitHub
      </a>
    </nav>
  </div>
</header>
<div class="docs-layout">
  <aside class="sidebar">
    <details class="navbox" open>
      <summary>Browse the docs</summary>
      <nav aria-label="Documentation">
{nav}
      </nav>
    </details>
    <script>if (matchMedia('(max-width: 900px)').matches) document.currentScript.previousElementSibling.open = false;</script>
  </aside>
  <main id="content" class="article">
    <nav class="crumbs" aria-label="Breadcrumb">{crumbs}</nav>
    <article>
{body}
    </article>
    {edit}
  </main>
  {toc}
</div>
<footer>
  <div class="wrap">
    <div class="credit">
      <h4>simoom</h4>
      <p>A small, fast HTTP/1.1, HTTP/2 and HTTP/3 server engine you build into Rust programs, with its own TLS 1.3 and nothing but the Rust standard library underneath. It is the HTTP engine of <a href="{host_root}cameleer/">Cameleer</a>.</p>
      <p>simoom is a <a href="{host_root}">Cameleering</a> project: carry more on less, no claim without a number.</p>
      <p>Apache License 2.0. simoom is independent of the Apache Software Foundation; Apache and Apache Camel are trademarks of the ASF.</p>
    </div>
    <div>
      <h4>Project</h4>
      <ul>
        <li><a href="{site_root}">simoom home</a></li>
        <li><a href="{site_root}use-cases/">Use cases</a></li>
        <li><a href="{site_root}benchmarks/">Benchmarks</a></li>
        <li><a href="{site_root}compare/">Compare</a></li>
        <li><a href="https://github.com/Cameleering/simoom">Source on GitHub</a></li>
        <li><a href="https://github.com/Cameleering/simoom/blob/main/CONTRIBUTING.md">Contributing</a></li>
      </ul>
    </div>
    <div>
      <h4>Docs</h4>
      <ul>
        <li><a href="{root}index.html">Docs home</a></li>
        <li><a href="{root}guides/index.html">Guides</a></li>
        <li><a href="{root}SECURITY.html">Security</a></li>
        <li><a href="https://docs.rs/simoom">API reference (docs.rs)</a></li>
        <li><a href="{site_root}llms.txt">llms.txt</a></li>
      </ul>
    </div>
  </div>
</footer>
<script src="{host_root}assets/docs.js" defer></script>
</body>
</html>
"""


def main(argv=None):
    here = os.path.dirname(os.path.abspath(__file__))
    repo = os.path.dirname(here)
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--docs", default=os.path.join(repo, "docs"), help="markdown tree (default: docs/)")
    ap.add_argument("--out", default=os.path.join(repo, "site", "simoom"), help="simoom site directory (default: site/simoom/)")
    ap.add_argument("--preview", help="also assemble a preview site in this directory")
    ap.add_argument("--cameleer-site", help="Cameleer's site/ directory, for the shared assets in the preview")
    args = ap.parse_args(argv)
    docs = os.path.abspath(args.docs)
    out = os.path.abspath(args.out)
    if not os.path.isdir(docs):
        print("error: %s is not a directory" % docs, file=sys.stderr)
        return 2
    site = Site(repo, docs, out)
    try:
        n, secs = site.build()
    except BuildError as e:
        print("error: %s" % e, file=sys.stderr)
        return 1
    print("built %d pages from %s into %s in %.1f s" % (n, docs, os.path.join(out, "docs"), secs))
    if args.preview:
        if not args.cameleer_site or not os.path.isdir(args.cameleer_site):
            print("error: --preview needs --cameleer-site pointing at Cameleer's site/ directory", file=sys.stderr)
            return 2
        prev = os.path.abspath(args.preview)
        if os.path.isdir(prev):
            shutil.rmtree(prev)
        shutil.copytree(args.cameleer_site, prev, ignore=shutil.ignore_patterns("llms-full.txt"))
        shutil.copytree(out, os.path.join(prev, "simoom"))
        print("preview assembled in %s (serve with: python -m http.server -d %s)" % (prev, prev))
    return 0


if __name__ == "__main__":
    sys.exit(main())
