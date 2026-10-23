"""Static extraction of every msgid used in the sources (shared by the completeness test)."""
import ast
import re
from pathlib import Path

SRC = Path(__file__).resolve().parent.parent / "src" / "periscope"
# function name -> index of the msgid argument
FUNCS = {"_": 0, "N_": 0, "pack": 0, "tr": 1, "translate": 1, "translate_html": 1}
TEMPLATE_CALL = re.compile(r"""\b_\(\s*(?:"((?:[^"\\]|\\.)*)"|'((?:[^'\\]|\\.)*)')""")


def py_msgids() -> tuple[set[str], list[str]]:
    """(msgids found as string literals, problems such as strings built at runtime)."""
    found, problems = set(), []
    for path in SRC.rglob("*.py"):
        if path.name == "i18n.py" or "locales" in path.parts:
            continue
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if not isinstance(node, ast.Call):
                continue
            f = node.func
            name = f.id if isinstance(f, ast.Name) else f.attr if isinstance(f, ast.Attribute) else None
            if name not in FUNCS or len(node.args) <= FUNCS[name]:
                continue
            arg = node.args[FUNCS[name]]
            if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                found.add(arg.value)
            elif isinstance(arg, ast.JoinedStr | ast.BinOp) or (
                    isinstance(arg, ast.Call) and isinstance(arg.func, ast.Attribute)
                    and arg.func.attr == "format"):
                problems.append(f"{path.name}:{node.lineno}: msgid built at runtime ({name})")
    return found, problems


def template_msgids() -> set[str]:
    found = set()
    for path in (SRC / "web" / "templates").glob("*.html"):
        for m in TEMPLATE_CALL.finditer(path.read_text(encoding="utf-8")):
            found.add(m.group(1) if m.group(1) is not None else m.group(2))
    return found


def used_msgids() -> set[str]:
    return py_msgids()[0] | template_msgids()
