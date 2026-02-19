"""
Kova Constraint Commitment Language (CCL) parser and evaluator.

Provides a complete pipeline for working with CCL: lexing, parsing,
evaluation, merging, narrowing validation, rate-limit checking, and
serialization.
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from typing import Any, Optional, Union


# ---------------------------------------------------------------------------
# Types
# ---------------------------------------------------------------------------

@dataclass
class Condition:
    """A simple condition comparing a context field to a value using an operator."""
    field: str
    operator: str
    value: Union[str, int, float, bool, list[str]]


@dataclass
class CompoundCondition:
    """A compound condition combining sub-conditions with boolean logic."""
    type: str  # "and", "or", "not"
    conditions: list[Union[Condition, "CompoundCondition"]]


@dataclass
class PermitDenyStatement:
    """A permit or deny statement granting or revoking access."""
    type: str  # "permit" or "deny"
    action: str
    resource: str
    condition: Optional[Union[Condition, CompoundCondition]] = None
    severity: str = "high"
    line: int = 0


@dataclass
class RequireStatement:
    """A require statement defining an obligation."""
    type: str  # always "require"
    action: str
    resource: str
    condition: Optional[Union[Condition, CompoundCondition]] = None
    severity: str = "high"
    line: int = 0


@dataclass
class LimitStatement:
    """A limit statement imposing a rate limit."""
    type: str  # always "limit"
    action: str
    count: int
    period_seconds: int
    severity: str = "high"
    line: int = 0


Statement = Union[PermitDenyStatement, RequireStatement, LimitStatement]


@dataclass
class CCLDocument:
    """A parsed CCL document containing categorized statement arrays."""
    statements: list[Statement] = field(default_factory=list)
    permits: list[PermitDenyStatement] = field(default_factory=list)
    denies: list[PermitDenyStatement] = field(default_factory=list)
    obligations: list[RequireStatement] = field(default_factory=list)
    limits: list[LimitStatement] = field(default_factory=list)


@dataclass
class EvaluationResult:
    """Result of evaluating a CCL document against an action/resource pair."""
    permitted: bool
    matched_rule: Optional[Statement] = None
    all_matches: list[Statement] = field(default_factory=list)
    reason: Optional[str] = None
    severity: Optional[str] = None


@dataclass
class RateLimitResult:
    """Result of checking a rate limit."""
    exceeded: bool
    limit: Optional[LimitStatement] = None
    remaining: float = float("inf")


@dataclass
class NarrowingViolation:
    """A violation found during narrowing validation."""
    child_rule: PermitDenyStatement
    parent_rule: PermitDenyStatement
    reason: str


@dataclass
class NarrowingResult:
    """Result of narrowing validation."""
    valid: bool
    violations: list[NarrowingViolation] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------

class CCLSyntaxError(Exception):
    """Raised when CCL source text contains a syntax error."""

    def __init__(self, message: str, line: int = 0, column: int = 0):
        self.line = line
        self.column = column
        super().__init__(f"CCL syntax error at line {line}, column {column}: {message}")


# ---------------------------------------------------------------------------
# Token types
# ---------------------------------------------------------------------------

@dataclass
class Token:
    type: str
    value: str
    line: int
    column: int


KEYWORDS: dict[str, str] = {
    "permit": "PERMIT",
    "deny": "DENY",
    "require": "REQUIRE",
    "limit": "LIMIT",
    "on": "ON",
    "when": "WHEN",
    "severity": "SEVERITY",
    "per": "PER",
    "seconds": "SECONDS",
    "second": "SECONDS",
    "minutes": "SECONDS",
    "minute": "SECONDS",
    "hours": "SECONDS",
    "hour": "SECONDS",
    "days": "SECONDS",
    "day": "SECONDS",
    "and": "AND",
    "or": "OR",
    "not": "NOT",
}

WORD_OPERATORS = {
    "contains",
    "not_contains",
    "in",
    "not_in",
    "matches",
    "starts_with",
    "ends_with",
}


# ---------------------------------------------------------------------------
# Lexer
# ---------------------------------------------------------------------------

def _is_ident_start(ch: str) -> bool:
    return ch.isalpha() or ch == "_"


def _is_ident_part(ch: str) -> bool:
    return ch.isalnum() or ch == "_"


def tokenize(source: str) -> list[Token]:
    """Tokenize CCL source code into an array of tokens."""
    tokens: list[Token] = []
    pos = 0
    line = 1
    column = 1
    length = len(source)

    def peek() -> str:
        return source[pos] if pos < length else ""

    def peek_at(offset: int) -> str:
        idx = pos + offset
        return source[idx] if idx < length else ""

    def advance() -> str:
        nonlocal pos, column
        ch = source[pos]
        pos += 1
        column += 1
        return ch

    def add_token(token_type: str, value: str, start_line: int, start_column: int) -> None:
        tokens.append(Token(type=token_type, value=value, line=start_line, column=start_column))

    while pos < length:
        ch = peek()

        # Skip spaces and tabs (not newlines)
        if ch in (" ", "\t", "\r"):
            advance()
            continue

        # Newlines
        if ch == "\n":
            start_line = line
            start_column = column
            advance()
            line += 1
            column = 1
            if tokens and tokens[-1].type != "NEWLINE":
                add_token("NEWLINE", "\n", start_line, start_column)
            continue

        # Comments: # until end of line
        if ch == "#":
            start_line = line
            start_column = column
            comment = ""
            while pos < length and peek() != "\n":
                comment += advance()
            add_token("COMMENT", comment, start_line, start_column)
            continue

        # Single-quoted strings
        if ch == "'":
            start_line = line
            start_column = column
            advance()  # consume opening quote
            s = ""
            while pos < length and peek() != "'":
                if peek() == "\n":
                    line += 1
                    column = 0
                s += advance()
            if pos < length:
                advance()  # consume closing quote
            add_token("STRING", s, start_line, start_column)
            continue

        # Parentheses
        if ch == "(":
            add_token("LPAREN", ch, line, column)
            advance()
            continue
        if ch == ")":
            add_token("RPAREN", ch, line, column)
            advance()
            continue

        # Brackets
        if ch == "[":
            add_token("LBRACKET", ch, line, column)
            advance()
            continue
        if ch == "]":
            add_token("RBRACKET", ch, line, column)
            advance()
            continue

        # Comma
        if ch == ",":
            add_token("COMMA", ch, line, column)
            advance()
            continue

        # Operators: !=, <=, >=, <, >, =
        if ch == "!" and peek_at(1) == "=":
            add_token("OPERATOR", "!=", line, column)
            advance()
            advance()
            continue
        if ch == "<" and peek_at(1) == "=":
            add_token("OPERATOR", "<=", line, column)
            advance()
            advance()
            continue
        if ch == ">" and peek_at(1) == "=":
            add_token("OPERATOR", ">=", line, column)
            advance()
            advance()
            continue
        if ch == "<":
            add_token("OPERATOR", "<", line, column)
            advance()
            continue
        if ch == ">":
            add_token("OPERATOR", ">", line, column)
            advance()
            continue
        if ch == "=":
            add_token("OPERATOR", "=", line, column)
            advance()
            continue

        # Wildcards: ** and *
        if ch == "*":
            start_line = line
            start_column = column
            advance()
            if pos < length and peek() == "*":
                advance()
                add_token("DOUBLE_WILDCARD", "**", start_line, start_column)
            else:
                add_token("WILDCARD", "*", start_line, start_column)
            continue

        # Numbers
        if ch.isdigit():
            start_line = line
            start_column = column
            num = ""
            while pos < length and peek().isdigit():
                num += advance()
            add_token("NUMBER", num, start_line, start_column)
            continue

        # Identifiers, keywords, and word operators
        if _is_ident_start(ch):
            start_line = line
            start_column = column
            ident = ""
            while pos < length and _is_ident_part(peek()):
                ident += advance()

            # Check for word operators
            if ident in WORD_OPERATORS:
                add_token("OPERATOR", ident, start_line, start_column)
                continue

            # Check for keywords
            lower = ident.lower()
            kw_type = KEYWORDS.get(lower)
            if kw_type is not None:
                add_token(kw_type, ident, start_line, start_column)
                continue

            add_token("IDENTIFIER", ident, start_line, start_column)
            continue

        # Dot
        if ch == ".":
            add_token("DOT", ch, line, column)
            advance()
            continue

        # Forward slash (resource paths)
        if ch == "/":
            start_line = line
            start_column = column
            path = ""
            while pos < length and peek() not in (" ", "\t", "\r", "\n"):
                path += advance()
            add_token("STRING", path, start_line, start_column)
            continue

        # Unknown character - skip
        advance()

    add_token("EOF", "", line, column)
    return tokens


# ---------------------------------------------------------------------------
# Time unit conversion
# ---------------------------------------------------------------------------

def _time_unit_multiplier(unit: str) -> int:
    unit_lower = unit.lower()
    if unit_lower in ("second", "seconds"):
        return 1
    if unit_lower in ("minute", "minutes"):
        return 60
    if unit_lower in ("hour", "hours"):
        return 3600
    if unit_lower in ("day", "days"):
        return 86400
    return 1


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

class _Parser:
    """Recursive descent parser for CCL tokens."""

    def __init__(self, tokens: list[Token]):
        self._tokens = tokens
        self._pos = 0

    def parse(self) -> CCLDocument:
        statements: list[Statement] = []
        self._skip_newlines_and_comments()

        while not self._is_at_end():
            tok = self._current()
            if tok.type in ("NEWLINE", "COMMENT"):
                self._advance()
                self._skip_newlines_and_comments()
                continue
            if tok.type == "EOF":
                break
            stmt = self._parse_statement()
            statements.append(stmt)
            self._skip_newlines_and_comments()

        return _build_document(statements)

    def _parse_statement(self) -> Statement:
        tok = self._current()
        if tok.type in ("PERMIT", "DENY"):
            return self._parse_permit_deny()
        if tok.type == "REQUIRE":
            return self._parse_require()
        if tok.type == "LIMIT":
            return self._parse_limit()
        raise CCLSyntaxError(
            f"Expected statement keyword (permit, deny, require, or limit), "
            f"but got '{tok.value}'",
            tok.line,
            tok.column,
        )

    def _parse_permit_deny(self) -> PermitDenyStatement:
        keyword = self._current()
        stmt_type = "permit" if keyword.type == "PERMIT" else "deny"
        stmt_line = keyword.line
        self._advance()

        action = self._parse_action()
        self._expect("ON", "Expected 'on' after action")
        resource = self._parse_resource()

        condition: Optional[Union[Condition, CompoundCondition]] = None
        if self._check("WHEN"):
            self._advance()
            condition = self._parse_condition()

        severity = "high"
        if self._check("SEVERITY"):
            self._advance()
            severity = self._parse_severity()

        return PermitDenyStatement(
            type=stmt_type,
            action=action,
            resource=resource,
            condition=condition,
            severity=severity,
            line=stmt_line,
        )

    def _parse_require(self) -> RequireStatement:
        keyword = self._current()
        stmt_line = keyword.line
        self._advance()

        action = self._parse_action()
        self._expect("ON", "Expected 'on' after action")
        resource = self._parse_resource()

        condition: Optional[Union[Condition, CompoundCondition]] = None
        if self._check("WHEN"):
            self._advance()
            condition = self._parse_condition()

        severity = "high"
        if self._check("SEVERITY"):
            self._advance()
            severity = self._parse_severity()

        return RequireStatement(
            type="require",
            action=action,
            resource=resource,
            condition=condition,
            severity=severity,
            line=stmt_line,
        )

    def _parse_limit(self) -> LimitStatement:
        keyword = self._current()
        stmt_line = keyword.line
        self._advance()

        action = self._parse_action()

        count_tok = self._current()
        if count_tok.type != "NUMBER":
            raise CCLSyntaxError(
                f"Expected count number after action in limit statement, "
                f"got '{count_tok.value}'",
                count_tok.line,
                count_tok.column,
            )
        count = int(count_tok.value)
        self._advance()

        self._expect("PER", "Expected 'per' in limit statement")

        period_tok = self._current()
        if period_tok.type != "NUMBER":
            raise CCLSyntaxError(
                f"Expected period number after 'per' in limit statement, "
                f"got '{period_tok.value}'",
                period_tok.line,
                period_tok.column,
            )
        raw_period = int(period_tok.value)
        self._advance()

        unit_tok = self._expect(
            "SECONDS",
            "Expected time unit (seconds, minutes, hours, days) in limit statement",
        )
        unit_multiplier = _time_unit_multiplier(unit_tok.value)
        period_seconds = raw_period * unit_multiplier

        severity = "high"
        if self._check("SEVERITY"):
            self._advance()
            severity = self._parse_severity()

        return LimitStatement(
            type="limit",
            action=action,
            count=count,
            period_seconds=period_seconds,
            severity=severity,
            line=stmt_line,
        )

    def _parse_action(self) -> str:
        parts: list[str] = []
        tok = self._current()

        if tok.type == "DOUBLE_WILDCARD":
            self._advance()
            return "**"

        if tok.type == "WILDCARD":
            parts.append("*")
            self._advance()
        elif tok.type == "IDENTIFIER":
            parts.append(tok.value)
            self._advance()
        else:
            raise CCLSyntaxError(
                f"Expected action identifier, got '{tok.value}'",
                tok.line,
                tok.column,
            )

        while self._check("DOT"):
            self._advance()  # consume dot
            nxt = self._current()
            if nxt.type == "IDENTIFIER":
                parts.append(nxt.value)
                self._advance()
            elif nxt.type == "WILDCARD":
                parts.append("*")
                self._advance()
            elif nxt.type == "DOUBLE_WILDCARD":
                parts.append("**")
                self._advance()
            else:
                raise CCLSyntaxError(
                    f"Expected identifier or wildcard after dot in action, got '{nxt.value}'",
                    nxt.line,
                    nxt.column,
                )

        return ".".join(parts)

    def _parse_resource(self) -> str:
        tok = self._current()

        if tok.type == "STRING":
            self._advance()
            return tok.value

        if tok.type == "WILDCARD":
            self._advance()
            return "*"

        if tok.type == "DOUBLE_WILDCARD":
            self._advance()
            return "**"

        if tok.type == "IDENTIFIER":
            self._advance()
            return tok.value

        raise CCLSyntaxError(
            f"Expected resource (string or pattern), got '{tok.value}'",
            tok.line,
            tok.column,
        )

    def _parse_condition(self) -> Union[Condition, CompoundCondition]:
        return self._parse_or_expr()

    def _parse_or_expr(self) -> Union[Condition, CompoundCondition]:
        left = self._parse_and_expr()

        while self._check("OR"):
            self._advance()
            right = self._parse_and_expr()
            if isinstance(left, CompoundCondition) and left.type == "or":
                left.conditions.append(right)
            else:
                left = CompoundCondition(type="or", conditions=[left, right])

        return left

    def _parse_and_expr(self) -> Union[Condition, CompoundCondition]:
        left = self._parse_not_expr()

        while self._check("AND"):
            self._advance()
            right = self._parse_not_expr()
            if isinstance(left, CompoundCondition) and left.type == "and":
                left.conditions.append(right)
            else:
                left = CompoundCondition(type="and", conditions=[left, right])

        return left

    def _parse_not_expr(self) -> Union[Condition, CompoundCondition]:
        if self._check("NOT"):
            self._advance()
            expr = self._parse_not_expr()
            return CompoundCondition(type="not", conditions=[expr])
        return self._parse_primary_cond()

    def _parse_primary_cond(self) -> Union[Condition, CompoundCondition]:
        if self._check("LPAREN"):
            self._advance()
            expr = self._parse_condition()
            self._expect("RPAREN", "Expected ')' after condition")
            return expr
        return self._parse_comparison()

    def _parse_comparison(self) -> Condition:
        field_name = self._parse_field()

        op_tok = self._current()
        if op_tok.type != "OPERATOR":
            raise CCLSyntaxError(
                f"Expected operator after field '{field_name}', got '{op_tok.value}'",
                op_tok.line,
                op_tok.column,
            )
        operator = op_tok.value
        self._advance()

        value = self._parse_value()
        return Condition(field=field_name, operator=operator, value=value)

    def _parse_field(self) -> str:
        tok = self._current()
        if tok.type != "IDENTIFIER":
            raise CCLSyntaxError(
                f"Expected field identifier, got '{tok.value}'",
                tok.line,
                tok.column,
            )

        name = tok.value
        self._advance()

        while self._check("DOT"):
            self._advance()
            nxt = self._current()
            if nxt.type != "IDENTIFIER":
                raise CCLSyntaxError(
                    f"Expected identifier after dot in field, got '{nxt.value}'",
                    nxt.line,
                    nxt.column,
                )
            name += "." + nxt.value
            self._advance()

        return name

    def _parse_value(self) -> Union[str, int, bool, list[str]]:
        tok = self._current()

        if tok.type == "STRING":
            self._advance()
            return tok.value

        if tok.type == "NUMBER":
            self._advance()
            return int(tok.value)

        if tok.type == "IDENTIFIER":
            if tok.value == "true":
                self._advance()
                return True
            if tok.value == "false":
                self._advance()
                return False
            self._advance()
            return tok.value

        if tok.type == "LBRACKET":
            return self._parse_array()

        raise CCLSyntaxError(
            f"Expected value (string, number, boolean, or array), got '{tok.value}'",
            tok.line,
            tok.column,
        )

    def _parse_array(self) -> list[str]:
        self._expect("LBRACKET", "Expected '['")
        values: list[str] = []

        if not self._check("RBRACKET"):
            first = self._parse_scalar_value()
            values.append(str(first))

            while self._check("COMMA"):
                self._advance()
                val = self._parse_scalar_value()
                values.append(str(val))

        self._expect("RBRACKET", "Expected ']'")
        return values

    def _parse_scalar_value(self) -> Union[str, int]:
        tok = self._current()
        if tok.type == "STRING":
            self._advance()
            return tok.value
        if tok.type == "NUMBER":
            self._advance()
            return int(tok.value)
        if tok.type == "IDENTIFIER":
            self._advance()
            return tok.value
        raise CCLSyntaxError(
            f"Expected scalar value in array, got '{tok.value}'",
            tok.line,
            tok.column,
        )

    def _parse_severity(self) -> str:
        tok = self._current()
        if tok.type != "IDENTIFIER":
            raise CCLSyntaxError(
                f"Expected severity level (critical, high, medium, low), got '{tok.value}'",
                tok.line,
                tok.column,
            )
        level = tok.value.lower()
        if level not in ("critical", "high", "medium", "low"):
            raise CCLSyntaxError(
                f"Invalid severity level '{tok.value}', expected critical, high, medium, or low",
                tok.line,
                tok.column,
            )
        self._advance()
        return level

    # -- Utility methods --

    def _current(self) -> Token:
        if self._pos >= len(self._tokens):
            return Token(type="EOF", value="", line=0, column=0)
        return self._tokens[self._pos]

    def _advance(self) -> Token:
        tok = self._current()
        if self._pos < len(self._tokens):
            self._pos += 1
        return tok

    def _check(self, token_type: str) -> bool:
        return self._current().type == token_type

    def _expect(self, token_type: str, message: str) -> Token:
        tok = self._current()
        if tok.type != token_type:
            got = "end of input" if tok.type == "EOF" else f"'{tok.value}' ({tok.type})"
            raise CCLSyntaxError(
                f"{message}, but got {got}",
                tok.line,
                tok.column,
            )
        return self._advance()

    def _is_at_end(self) -> bool:
        return self._current().type == "EOF"

    def _skip_newlines_and_comments(self) -> None:
        while (
            self._pos < len(self._tokens)
            and self._current().type in ("NEWLINE", "COMMENT")
        ):
            self._pos += 1


def _build_document(statements: list[Statement]) -> CCLDocument:
    """Build a CCLDocument from a list of statements."""
    permits: list[PermitDenyStatement] = []
    denies: list[PermitDenyStatement] = []
    obligations: list[RequireStatement] = []
    limits: list[LimitStatement] = []

    for stmt in statements:
        if isinstance(stmt, PermitDenyStatement):
            if stmt.type == "permit":
                permits.append(stmt)
            else:
                denies.append(stmt)
        elif isinstance(stmt, RequireStatement):
            obligations.append(stmt)
        elif isinstance(stmt, LimitStatement):
            limits.append(stmt)

    return CCLDocument(
        statements=statements,
        permits=permits,
        denies=denies,
        obligations=obligations,
        limits=limits,
    )


# ---------------------------------------------------------------------------
# Public parse function
# ---------------------------------------------------------------------------

def parse(source: str) -> CCLDocument:
    """Parse CCL source text into a CCLDocument AST.

    Args:
        source: CCL source text containing one or more statements.

    Returns:
        A parsed CCLDocument with categorized statement arrays.

    Raises:
        CCLSyntaxError: When the input is empty or contains syntax errors.
    """
    if not source or source.strip() == "":
        raise CCLSyntaxError(
            "CCL parse error: input is empty. Provide at least one statement, "
            "e.g.: permit read on '/data/**'",
            1,
            1,
        )
    tokens = tokenize(source)
    parser = _Parser(tokens)
    return parser.parse()


# ---------------------------------------------------------------------------
# Pattern matching
# ---------------------------------------------------------------------------

def _match_segments(
    pattern: list[str], pi: int, target: list[str], ti: int
) -> bool:
    """Generic segment matcher supporting * (single) and ** (multi) wildcards."""
    while pi < len(pattern) and ti < len(target):
        p = pattern[pi]

        if p == "**":
            # ** can match zero or more segments
            if _match_segments(pattern, pi + 1, target, ti):
                return True
            return _match_segments(pattern, pi, target, ti + 1)

        if p == "*":
            # * matches exactly one segment (any content)
            pi += 1
            ti += 1
            continue

        # Literal match
        if p != target[ti]:
            return False

        pi += 1
        ti += 1

    # Skip trailing ** patterns (they can match zero segments)
    while pi < len(pattern) and pattern[pi] == "**":
        pi += 1

    return pi == len(pattern) and ti == len(target)


def match_action(pattern: str, action: str) -> bool:
    """Match an action string against a dot-separated pattern.

    Segments are split on '.'. Wildcard rules:
    - '*' matches exactly one segment
    - '**' matches zero or more segments

    Args:
        pattern: The action pattern (e.g. "file.*", "**").
        action: The concrete action string (e.g. "file.read").

    Returns:
        True if the action matches the pattern.
    """
    pattern_parts = pattern.split(".")
    action_parts = action.split(".")
    return _match_segments(pattern_parts, 0, action_parts, 0)


def match_resource(pattern: str, resource: str) -> bool:
    """Match a resource path against a slash-separated pattern.

    Segments are split on '/'. Leading/trailing slashes are normalized.
    Wildcard rules:
    - '*' matches exactly one path segment
    - '**' matches zero or more segments

    Args:
        pattern: The resource pattern (e.g. "/data/**", "/api/*").
        resource: The concrete resource path.

    Returns:
        True if the resource matches the pattern.
    """
    norm_pattern = pattern.strip("/")
    norm_resource = resource.strip("/")

    if norm_pattern == "" and norm_resource == "":
        return True
    if norm_pattern == "**":
        return True
    if norm_pattern == "*" and "/" not in norm_resource:
        return True

    pattern_parts = norm_pattern.split("/")
    resource_parts = norm_resource.split("/")
    return _match_segments(pattern_parts, 0, resource_parts, 0)


# ---------------------------------------------------------------------------
# Specificity
# ---------------------------------------------------------------------------

def specificity(action_pattern: str, resource_pattern: str) -> int:
    """Calculate the specificity score of an action+resource pattern pair.

    More specific patterns produce higher scores:
    - Literal segment: 2 points
    - Single wildcard (*): 1 point
    - Double wildcard (**): 0 points
    """
    score = 0

    action_parts = action_pattern.split(".")
    for part in action_parts:
        if part == "**":
            score += 0
        elif part == "*":
            score += 1
        else:
            score += 2

    norm_resource = resource_pattern.strip("/")
    if norm_resource:
        resource_parts = norm_resource.split("/")
        for part in resource_parts:
            if part == "**":
                score += 0
            elif part == "*":
                score += 1
            else:
                score += 2

    return score


# ---------------------------------------------------------------------------
# Condition evaluation
# ---------------------------------------------------------------------------

def _resolve_field(context: dict, field_name: str) -> Any:
    """Resolve a dotted field path against a context dict."""
    parts = field_name.split(".")
    current: Any = context
    for part in parts:
        if current is None or not isinstance(current, dict):
            return None
        current = current.get(part)
    return current


def evaluate_condition(
    condition: Union[Condition, CompoundCondition], context: dict
) -> bool:
    """Evaluate a simple or compound condition against a context object."""
    if isinstance(condition, CompoundCondition):
        return _evaluate_compound_condition(condition, context)
    return _evaluate_simple_condition(condition, context)


def _evaluate_compound_condition(
    condition: CompoundCondition, context: dict
) -> bool:
    if condition.type == "and":
        return all(evaluate_condition(c, context) for c in condition.conditions)
    if condition.type == "or":
        return any(evaluate_condition(c, context) for c in condition.conditions)
    if condition.type == "not":
        return not evaluate_condition(condition.conditions[0], context)
    return False


def _evaluate_simple_condition(condition: Condition, context: dict) -> bool:
    field_value = _resolve_field(context, condition.field)

    if field_value is None:
        return False

    op = condition.operator
    value = condition.value

    if op == "=":
        return field_value == value
    if op == "!=":
        return field_value != value
    if op == "<":
        return isinstance(field_value, (int, float)) and isinstance(value, (int, float)) and field_value < value
    if op == ">":
        return isinstance(field_value, (int, float)) and isinstance(value, (int, float)) and field_value > value
    if op == "<=":
        return isinstance(field_value, (int, float)) and isinstance(value, (int, float)) and field_value <= value
    if op == ">=":
        return isinstance(field_value, (int, float)) and isinstance(value, (int, float)) and field_value >= value
    if op == "contains":
        if isinstance(field_value, str) and isinstance(value, str):
            return value in field_value
        if isinstance(field_value, list):
            return value in field_value
        return False
    if op == "not_contains":
        if isinstance(field_value, str) and isinstance(value, str):
            return value not in field_value
        if isinstance(field_value, list):
            return value not in field_value
        return True
    if op == "in":
        if isinstance(value, list):
            return str(field_value) in value
        return False
    if op == "not_in":
        if isinstance(value, list):
            return str(field_value) not in value
        return True
    if op == "matches":
        if isinstance(field_value, str) and isinstance(value, str):
            try:
                return bool(re.search(value, field_value))
            except re.error:
                return False
        return False
    if op == "starts_with":
        return isinstance(field_value, str) and isinstance(value, str) and field_value.startswith(value)
    if op == "ends_with":
        return isinstance(field_value, str) and isinstance(value, str) and field_value.endswith(value)

    return False


# ---------------------------------------------------------------------------
# Evaluate
# ---------------------------------------------------------------------------

def evaluate(
    doc: CCLDocument,
    action: str,
    resource: str,
    context: Optional[dict] = None,
) -> EvaluationResult:
    """Evaluate a CCL document against an action/resource pair.

    Resolution order:
    1. Find all matching statements (action + resource match, conditions pass)
    2. Sort by specificity (most specific first)
    3. At equal specificity, deny wins over permit
    4. If no rules match, default is deny (permitted=False)

    Args:
        doc: The parsed CCL document.
        action: The action being attempted.
        resource: The target resource path.
        context: Optional context for condition evaluation.

    Returns:
        An EvaluationResult with permitted, matched_rule, and all_matches.
    """
    ctx = context or {}
    all_matches: list[Statement] = []
    matched_permit_deny: list[PermitDenyStatement] = []

    for stmt in doc.permits:
        if match_action(stmt.action, action) and match_resource(stmt.resource, resource):
            if stmt.condition is None or evaluate_condition(stmt.condition, ctx):
                matched_permit_deny.append(stmt)
                all_matches.append(stmt)

    for stmt in doc.denies:
        if match_action(stmt.action, action) and match_resource(stmt.resource, resource):
            if stmt.condition is None or evaluate_condition(stmt.condition, ctx):
                matched_permit_deny.append(stmt)
                all_matches.append(stmt)

    for stmt in doc.obligations:
        if match_action(stmt.action, action) and match_resource(stmt.resource, resource):
            if stmt.condition is None or evaluate_condition(stmt.condition, ctx):
                all_matches.append(stmt)

    if not matched_permit_deny:
        return EvaluationResult(
            permitted=False,
            all_matches=all_matches,
            reason="No matching rules found; default deny",
        )

    # Sort by specificity descending; at equal specificity, denies come first
    def _sort_key(s: PermitDenyStatement) -> tuple[int, int]:
        spec = specificity(s.action, s.resource)
        deny_priority = 0 if s.type == "deny" else 1
        return (-spec, deny_priority)

    matched_permit_deny.sort(key=_sort_key)

    winner = matched_permit_deny[0]
    permitted = winner.type == "permit"

    return EvaluationResult(
        permitted=permitted,
        matched_rule=winner,
        all_matches=all_matches,
        reason=f"Matched {winner.type} rule for {winner.action} on {winner.resource}",
        severity=winner.severity,
    )


# ---------------------------------------------------------------------------
# Rate-limit checking
# ---------------------------------------------------------------------------

def check_rate_limit(
    doc: CCLDocument,
    metric: str,
    current_count: int,
    window_start_ms: int,
    now_ms: Optional[int] = None,
) -> RateLimitResult:
    """Check whether an action has exceeded its rate limit.

    Args:
        doc: The parsed CCL document with limit statements.
        metric: The action to check.
        current_count: How many times the action has been invoked in the current window.
        window_start_ms: Epoch milliseconds when the current window started.
        now_ms: Optional current time in epoch ms (defaults to current time).

    Returns:
        A RateLimitResult with exceeded, limit, and remaining.
    """
    current_time = now_ms if now_ms is not None else int(time.time() * 1000)

    matched_limit: Optional[LimitStatement] = None
    best_spec = -1

    for limit in doc.limits:
        if match_action(limit.action, metric):
            spec = specificity(limit.action, "")
            if spec > best_spec:
                best_spec = spec
                matched_limit = limit

    if matched_limit is None:
        return RateLimitResult(exceeded=False, remaining=float("inf"))

    period_ms = matched_limit.period_seconds * 1000
    elapsed = current_time - window_start_ms

    if elapsed > period_ms:
        return RateLimitResult(
            exceeded=False,
            limit=matched_limit,
            remaining=float(matched_limit.count),
        )

    remaining = max(0, matched_limit.count - current_count)
    return RateLimitResult(
        exceeded=current_count >= matched_limit.count,
        limit=matched_limit,
        remaining=float(remaining),
    )


# ---------------------------------------------------------------------------
# Narrowing validation
# ---------------------------------------------------------------------------

def _patterns_overlap(pattern1: str, pattern2: str) -> bool:
    """Check if two patterns can match any of the same strings."""
    if pattern1 == "**" or pattern2 == "**":
        return True
    if pattern1 == "*" or pattern2 == "*":
        return True
    if pattern1 == pattern2:
        return True

    concrete1 = pattern1.replace("**", "x").replace("*", "x")
    concrete2 = pattern2.replace("**", "x").replace("*", "x")

    sep1 = "/" if "/" in pattern1 else "."
    sep2 = "/" if "/" in pattern2 else "."
    fn1 = match_resource if sep1 == "/" else match_action
    fn2 = match_resource if sep2 == "/" else match_action

    return fn1(pattern1, concrete2) or fn2(pattern2, concrete1)


def _is_subset_segments(
    child: list[str], ci: int, parent: list[str], pi: int
) -> bool:
    """Check if child segments are a subset of parent segments."""
    if ci == len(child) and pi == len(parent):
        return True
    if pi == len(parent):
        return False
    if ci == len(child):
        for i in range(pi, len(parent)):
            if parent[i] != "**":
                return False
        return True

    p_seg = parent[pi]
    c_seg = child[ci]

    if p_seg == "**":
        if _is_subset_segments(child, ci, parent, pi + 1):
            return True
        return _is_subset_segments(child, ci + 1, parent, pi)

    if c_seg == "**":
        if p_seg != "**":
            return False
        return _is_subset_segments(child, ci + 1, parent, pi + 1)

    if p_seg == "*":
        return _is_subset_segments(child, ci + 1, parent, pi + 1)

    if c_seg == "*":
        if p_seg != "*" and p_seg != "**":
            return False
        return _is_subset_segments(child, ci + 1, parent, pi + 1)

    if c_seg != p_seg:
        return False
    return _is_subset_segments(child, ci + 1, parent, pi + 1)


def _is_subset_pattern(child_pattern: str, parent_pattern: str, separator: str) -> bool:
    """Check if child_pattern is a subset of (at most as broad as) parent_pattern."""
    if parent_pattern == "**":
        return True
    if child_pattern == "**" and parent_pattern != "**":
        return False

    child_parts = [p for p in child_pattern.split(separator) if p]
    parent_parts = [p for p in parent_pattern.split(separator) if p]
    return _is_subset_segments(child_parts, 0, parent_parts, 0)


def validate_narrowing(
    parent_doc: CCLDocument, child_doc: CCLDocument
) -> NarrowingResult:
    """Validate that a child CCL document only narrows (restricts) the parent.

    A valid delegation chain requires that each child can only make
    constraints more restrictive, never broader.

    Args:
        parent_doc: The parent (broader) CCL document.
        child_doc: The child (narrower) CCL document.

    Returns:
        A NarrowingResult with valid and violations.
    """
    violations: list[NarrowingViolation] = []

    for child_permit in child_doc.permits:
        for parent_deny in parent_doc.denies:
            if (
                _patterns_overlap(child_permit.action, parent_deny.action)
                and _patterns_overlap(child_permit.resource, parent_deny.resource)
            ):
                violations.append(
                    NarrowingViolation(
                        child_rule=child_permit,
                        parent_rule=parent_deny,
                        reason=(
                            f"Child permits '{child_permit.action}' on "
                            f"'{child_permit.resource}' which parent denies"
                        ),
                    )
                )

        has_matching_parent_permit = False
        for parent_permit in parent_doc.permits:
            if (
                _is_subset_pattern(child_permit.action, parent_permit.action, ".")
                and _is_subset_pattern(child_permit.resource, parent_permit.resource, "/")
            ):
                has_matching_parent_permit = True
                break

        if parent_doc.permits and not has_matching_parent_permit:
            closest_parent = parent_doc.permits[0]
            violations.append(
                NarrowingViolation(
                    child_rule=child_permit,
                    parent_rule=closest_parent,
                    reason=(
                        f"Child permit '{child_permit.action}' on "
                        f"'{child_permit.resource}' is not a subset of any parent permit"
                    ),
                )
            )

    return NarrowingResult(
        valid=len(violations) == 0,
        violations=violations,
    )


# ---------------------------------------------------------------------------
# Merge
# ---------------------------------------------------------------------------

def merge(parent: CCLDocument, child: CCLDocument) -> CCLDocument:
    """Merge a parent and child CCL document with deny-wins semantics.

    Args:
        parent: The parent (broader) CCL document.
        child: The child (narrower) CCL document.

    Returns:
        A new merged CCLDocument.
    """
    statements: list[Statement] = []

    # All denies from both
    statements.extend(parent.denies)
    statements.extend(child.denies)

    # All permits from both
    statements.extend(child.permits)
    statements.extend(parent.permits)

    # All obligations from both
    statements.extend(parent.obligations)
    statements.extend(child.obligations)

    # Limits: take the more restrictive for each action
    limits_by_action: dict[str, LimitStatement] = {}
    for limit in parent.limits:
        existing = limits_by_action.get(limit.action)
        if existing is None or limit.count < existing.count:
            limits_by_action[limit.action] = limit
    for limit in child.limits:
        existing = limits_by_action.get(limit.action)
        if existing is None or limit.count < existing.count:
            limits_by_action[limit.action] = limit

    statements.extend(limits_by_action.values())

    return _build_document(statements)


# ---------------------------------------------------------------------------
# Serialize
# ---------------------------------------------------------------------------

def _best_time_unit(seconds: int) -> tuple[int, str]:
    """Convert seconds to the most natural time unit."""
    if seconds % 86400 == 0 and seconds >= 86400:
        return seconds // 86400, "days"
    if seconds % 3600 == 0 and seconds >= 3600:
        return seconds // 3600, "hours"
    if seconds % 60 == 0 and seconds >= 60:
        return seconds // 60, "minutes"
    return seconds, "seconds"


def _serialize_condition(cond: Union[Condition, CompoundCondition]) -> str:
    """Serialize a condition to CCL syntax."""
    if isinstance(cond, CompoundCondition):
        if cond.type == "not":
            return f"not {_serialize_condition(cond.conditions[0])}"
        parts = []
        for c in cond.conditions:
            if isinstance(c, CompoundCondition) and c.type != cond.type:
                parts.append(f"({_serialize_condition(c)})")
            else:
                parts.append(_serialize_condition(c))
        return f" {cond.type} ".join(parts)

    # Simple condition
    value_str = _serialize_value(cond.value)
    return f"{cond.field} {cond.operator} {value_str}"


def _serialize_value(value: Any) -> str:
    """Serialize a condition value."""
    if isinstance(value, list):
        items = [f"'{v}'" for v in value]
        return f"[{', '.join(items)}]"
    if isinstance(value, str):
        return f"'{value}'"
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def _serialize_statement(stmt: Statement) -> str:
    """Serialize a single statement to CCL syntax."""
    if isinstance(stmt, PermitDenyStatement):
        line = f"{stmt.type} {stmt.action} on '{stmt.resource}'"
        if stmt.condition is not None:
            line += f" when {_serialize_condition(stmt.condition)}"
        if stmt.severity != "high":
            line += f" severity {stmt.severity}"
        return line

    if isinstance(stmt, RequireStatement):
        line = f"require {stmt.action} on '{stmt.resource}'"
        if stmt.condition is not None:
            line += f" when {_serialize_condition(stmt.condition)}"
        if stmt.severity != "high":
            line += f" severity {stmt.severity}"
        return line

    if isinstance(stmt, LimitStatement):
        value, unit = _best_time_unit(stmt.period_seconds)
        line = f"limit {stmt.action} {stmt.count} per {value} {unit}"
        if stmt.severity != "high":
            line += f" severity {stmt.severity}"
        return line

    return ""


def serialize(doc: CCLDocument) -> str:
    """Serialize a CCLDocument back to human-readable CCL source text.

    Args:
        doc: The CCL document to serialize.

    Returns:
        A multi-line CCL source string.
    """
    lines = [_serialize_statement(stmt) for stmt in doc.statements]
    return "\n".join(lines)
