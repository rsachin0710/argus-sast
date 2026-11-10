"""Code index: functions per file (tree-sitter), chunking, and lookups.

What the index gives the rest of Argus
--------------------------------------
* ``FileIndex.functions``  every function/method/arrow-function with its line
  span, used to (a) cut large files into function-aligned chunks for the
  Hunter agents, (b) name the enclosing function in a finding's fingerprint,
  and (c) pick the code window the Verifier and Remediator see.
* ``CodeIndex.get_symbol`` / ``find_callers`` / ``search`` / ``read_lines``
  back the Tracer agent's read-only tools.

If tree-sitter is unavailable for some reason, Argus degrades gracefully to
fixed-size line windows (findings still work; context is just less precise).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from .config import Language
from .security import redact_lines
from .targets import SourceFile

try:
    import tree_sitter_java
    import tree_sitter_javascript
    import tree_sitter_python
    from tree_sitter import Language as TSLanguage
    from tree_sitter import Parser

    _TS_LANGS = {
        Language.JAVA: TSLanguage(tree_sitter_java.language()),
        Language.PYTHON: TSLanguage(tree_sitter_python.language()),
        Language.JAVASCRIPT: TSLanguage(tree_sitter_javascript.language()),
    }
    HAVE_TREE_SITTER = True
except Exception:  # pragma: no cover - exercised only without tree-sitter
    _TS_LANGS = {}
    HAVE_TREE_SITTER = False

_FUNC_NODES = {
    Language.JAVA: {"method_declaration", "constructor_declaration", "lambda_expression"},
    Language.PYTHON: {"function_definition"},
    Language.JAVASCRIPT: {
        "function_declaration",
        "function_expression",
        "function",
        "arrow_function",
        "method_definition",
        "generator_function_declaration",
    },
}
_CLASS_NODES = {"class_declaration", "class_definition", "interface_declaration", "enum_declaration", "class"}


@dataclass
class Function:
    name: str
    start_line: int  # 1-based, inclusive (includes decorators/annotations)
    end_line: int
    class_name: str | None = None
    depth: int = 0  # nesting depth among functions (0 = outermost)

    @property
    def qualified(self) -> str:
        return f"{self.class_name}.{self.name}" if self.class_name else self.name


@dataclass
class Chunk:
    file: str
    language: Language
    start_line: int
    end_line: int
    header_end: int = 0  # >0: lines 1..header_end are sent as extra context

    @property
    def id(self) -> str:
        return f"{self.file}:{self.start_line}-{self.end_line}"


@dataclass
class FileIndex:
    source: SourceFile
    functions: list[Function] = field(default_factory=list)
    redacted: list[str] = field(default_factory=list)
    redactions: int = 0
    parse_error: bool = False

    @property
    def rel_path(self) -> str:
        return self.source.rel_path

    @property
    def lines(self) -> list[str]:
        return self.source.lines

    def enclosing_function(self, line: int) -> Function | None:
        """Innermost function containing `line`."""
        best = None
        for fn in self.functions:
            if fn.start_line <= line <= fn.end_line:
                if best is None or (fn.end_line - fn.start_line) < (best.end_line - best.start_line):
                    best = fn
        return best

    def outer_function(self, line: int) -> Function | None:
        """Outermost *named* function containing `line` (skips anonymous lambdas)."""
        cands = [f for f in self.functions if f.start_line <= line <= f.end_line and not f.name.startswith("<")]
        if not cands:
            return self.enclosing_function(line)
        return min(cands, key=lambda f: f.depth)

    def window_for(self, line: int, max_lines: int = 160, pad: int = 8) -> tuple[int, int]:
        """Code window around `line` for the Verifier/Remediator: the enclosing
        named function (+pad lines) or ±40 lines, capped at `max_lines`."""
        n = len(self.lines)
        fn = self.outer_function(line)
        if fn and (fn.end_line - fn.start_line) <= max_lines:
            start, end = max(1, fn.start_line - pad), min(n, fn.end_line + pad)
        else:
            start, end = max(1, line - 40), min(n, line + 40)
        if end - start + 1 > max_lines:
            half = max_lines // 2
            start, end = max(1, line - half), min(n, line + half)
        return start, end


# --------------------------------------------------------------------------- #
# Parsing
# --------------------------------------------------------------------------- #
def _node_name(node, src: bytes, language: Language) -> str:
    name_node = node.child_by_field_name("name")
    if name_node is not None:
        return src[name_node.start_byte : name_node.end_byte].decode("utf-8", "replace")
    parent = node.parent
    # const handler = (req, res) => {...}
    if parent is not None and parent.type in ("variable_declarator", "assignment_expression", "pair"):
        key = parent.child_by_field_name("name") or parent.child_by_field_name("left") or parent.child_by_field_name("key")
        if key is not None:
            return src[key.start_byte : key.end_byte].decode("utf-8", "replace")[:60]
    # app.get("/users", (req, res) => {...})  ->  <app.get "/users">
    if parent is not None and parent.type == "arguments" and parent.parent is not None:
        call = parent.parent
        fn = call.child_by_field_name("function")
        label = src[fn.start_byte : fn.end_byte].decode("utf-8", "replace")[:40] if fn is not None else "call"
        first = parent.named_children[0] if parent.named_children else None
        if first is not None and first.type in ("string", "template_string") and first is not node:
            label += " " + src[first.start_byte : first.end_byte].decode("utf-8", "replace")[:40]
        return f"<{label}>"
    return "<anonymous>"


def _extract_functions(language: Language, text: str) -> tuple[list[Function], bool]:
    if not HAVE_TREE_SITTER:
        return [], False
    src = text.encode("utf-8", "replace")
    parser = Parser(_TS_LANGS[language])
    tree = parser.parse(src)
    funcs: list[Function] = []
    func_types = _FUNC_NODES[language]

    def walk(node, class_name: str | None, depth: int) -> None:
        for child in node.children:
            if not child.is_named:
                continue  # keyword tokens such as the literal `function`
            t = child.type
            if t in _CLASS_NODES:
                name_node = child.child_by_field_name("name")
                cname = (
                    src[name_node.start_byte : name_node.end_byte].decode("utf-8", "replace")
                    if name_node is not None
                    else class_name
                )
                walk(child, cname, depth)
            elif t in func_types:
                # Include decorators (Python) / annotations are part of Java modifiers already.
                start_node = child.parent if child.parent is not None and child.parent.type == "decorated_definition" else child
                fn = Function(
                    name=_node_name(child, src, language),
                    start_line=start_node.start_point[0] + 1,
                    end_line=child.end_point[0] + 1,
                    class_name=class_name,
                    depth=depth,
                )
                # Skip tiny one-line lambdas as standalone units: they add noise.
                if not (t in ("lambda_expression", "arrow_function") and fn.start_line == fn.end_line):
                    funcs.append(fn)
                walk(child, class_name, depth + 1)
            else:
                walk(child, class_name, depth)

    walk(tree.root_node, None, 0)
    funcs.sort(key=lambda f: (f.start_line, -f.end_line))
    return funcs, tree.root_node.has_error


def has_syntax_error(language: Language, text: str) -> bool:
    """Used to validate remediation patches for Java/JS (Python uses ast)."""
    if not HAVE_TREE_SITTER:
        return False
    tree = Parser(_TS_LANGS[language]).parse(text.encode("utf-8", "replace"))
    return tree.root_node.has_error


def header_end(lines: list[str], language: Language, limit: int = 40) -> int:
    """Last line of the import/package block (sent as context with each chunk)."""
    last = 0
    pat = {
        Language.PYTHON: re.compile(r"^\s*(import|from)\s+\S+"),
        Language.JAVA: re.compile(r"^\s*(package|import)\s+[\w.*]+"),
        Language.JAVASCRIPT: re.compile(r"^\s*(import\s|const\s+.*=\s*require\(|.*require\(['\"])"),
    }[language]
    for i, line in enumerate(lines[: limit * 3]):
        if pat.match(line):
            last = i + 1
    return min(last, limit)


# --------------------------------------------------------------------------- #
# Index over all files
# --------------------------------------------------------------------------- #
class CodeIndex:
    def __init__(self, files: list[SourceFile], redact: bool = True):
        self.files: dict[str, FileIndex] = {}
        for sf in files:
            funcs, err = _extract_functions(sf.language, sf.text)
            if redact:
                redacted, n = redact_lines(sf.lines)
            else:
                redacted, n = list(sf.lines), 0
            self.files[sf.rel_path] = FileIndex(sf, funcs, redacted, n, err)
        # name -> [(file, Function)] for the Tracer's get_symbol tool
        self.symbols: dict[str, list[tuple[str, Function]]] = {}
        for rel, fi in self.files.items():
            for fn in fi.functions:
                if fn.name.startswith("<"):
                    continue
                self.symbols.setdefault(fn.name, []).append((rel, fn))

    # -- chunking -------------------------------------------------------------
    def chunks(self, max_lines: int) -> list[Chunk]:
        out: list[Chunk] = []
        for rel in sorted(self.files):
            out.extend(self._chunk_file(self.files[rel], max_lines))
        return out

    def _chunk_file(self, fi: FileIndex, max_lines: int) -> list[Chunk]:
        n = len(fi.lines)
        lang = fi.source.language
        if n == 0:
            return []
        if n <= max_lines:
            return [Chunk(fi.rel_path, lang, 1, n)]
        hdr = header_end(fi.lines, lang)
        # Outermost functions define natural cut points.
        outer = [f for f in fi.functions if f.depth == 0]
        cuts: list[tuple[int, int]] = []
        cursor = 1
        for fn in outer:
            if fn.start_line < cursor:
                continue
            if fn.start_line > cursor:
                cuts.append((cursor, fn.start_line - 1))  # code between functions
            cuts.append((fn.start_line, fn.end_line))
            cursor = fn.end_line + 1
        if cursor <= n:
            cuts.append((cursor, n))
        # Pack consecutive pieces into chunks of <= max_lines; split giant pieces.
        chunks: list[Chunk] = []
        cur_start, cur_end = None, None
        for s, e in cuts:
            if e - s + 1 > max_lines:
                if cur_start is not None:
                    chunks.append(Chunk(fi.rel_path, lang, cur_start, cur_end, hdr))
                    cur_start = None
                step = max_lines - 20  # 20-line overlap so nothing falls on a seam
                for ws in range(s, e + 1, step):
                    chunks.append(Chunk(fi.rel_path, lang, ws, min(e, ws + max_lines - 1), hdr))
                    if ws + max_lines - 1 >= e:
                        break
                continue
            if cur_start is None:
                cur_start, cur_end = s, e
            elif e - cur_start + 1 <= max_lines:
                cur_end = e
            else:
                chunks.append(Chunk(fi.rel_path, lang, cur_start, cur_end, hdr))
                cur_start, cur_end = s, e
        if cur_start is not None:
            chunks.append(Chunk(fi.rel_path, lang, cur_start, cur_end, hdr))
        for c in chunks:
            if c.start_line == 1:
                c.header_end = 0  # header already inside the chunk
        return chunks

    # -- Tracer tool backends (read-only, redacted text) ----------------------------
    def read_lines(self, rel: str, start: int, end: int, cap: int = 200) -> str:
        fi = self.files.get(rel)
        if fi is None:
            return f"ERROR: file {rel!r} is not part of this scan. Known files: {', '.join(list(self.files)[:30])}"
        n = len(fi.redacted)
        start = max(1, int(start))
        end = min(n, int(end), start + cap - 1)
        if start > n:
            return f"ERROR: {rel} has only {n} lines"
        from .security import number_lines

        return number_lines(fi.redacted[start - 1 : end], start)

    def get_symbol(self, name: str, cap: int = 3) -> str:
        name = name.split(".")[-1].split("(")[0].strip()
        defs = self.symbols.get(name, [])
        if not defs:
            return f"No definition of {name!r} found in the scanned files."
        parts = []
        for rel, fn in defs[:cap]:
            parts.append(f"--- {rel} ({fn.qualified}, lines {fn.start_line}-{fn.end_line}) ---")
            parts.append(self.read_lines(rel, fn.start_line, min(fn.end_line, fn.start_line + 120)))
        if len(defs) > cap:
            parts.append(f"... {len(defs) - cap} more definitions not shown")
        return "\n".join(parts)

    def find_callers(self, name: str, cap: int = 25) -> str:
        name = name.split(".")[-1].split("(")[0].strip()
        if not re.fullmatch(r"[A-Za-z_$][\w$]*", name):
            return "ERROR: give a plain function name"
        rx = re.compile(rf"(?<![\w$]){re.escape(name)}\s*\(")
        hits = []
        for rel in sorted(self.files):
            fi = self.files[rel]
            for i, line in enumerate(fi.redacted):
                if rx.search(line):
                    fn = fi.enclosing_function(i + 1)
                    if fn and fn.name == name and fn.start_line == i + 1:
                        continue  # the definition itself
                    where = f" in {fn.qualified}" if fn else ""
                    hits.append(f"{rel}:{i + 1}{where}: {line.strip()[:160]}")
                    if len(hits) >= cap:
                        return "\n".join(hits) + "\n... (truncated)"
        return "\n".join(hits) if hits else f"No calls to {name!r} found."

    def search(self, pattern: str, cap: int = 30) -> str:
        try:
            rx = re.compile(pattern[:200])
        except re.error as exc:
            return f"ERROR: invalid regex: {exc}"
        hits = []
        for rel in sorted(self.files):
            for i, line in enumerate(self.files[rel].redacted):
                if len(line) > 2000:
                    continue
                if rx.search(line):
                    hits.append(f"{rel}:{i + 1}: {line.strip()[:160]}")
                    if len(hits) >= cap:
                        return "\n".join(hits) + "\n... (truncated)"
        return "\n".join(hits) if hits else "No matches."
