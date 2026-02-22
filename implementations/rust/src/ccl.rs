//! Covenant Constraint Language (CCL) parser and evaluator.
//!
//! CCL is a domain-specific language for expressing access control policies
//! in Kervyx covenants. It supports four statement types:
//!
//! - `permit <action> on <resource>` -- allow access
//! - `deny <action> on <resource>` -- deny access
//! - `require <action> on <resource>` -- obligation
//! - `limit <action> <count> per <period> <unit>` -- rate limit
//!
//! Evaluation semantics: default deny, deny wins at equal specificity,
//! most specific matching rule takes precedence.

use crate::KervyxError;
use std::collections::HashMap;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// The four CCL statement types.
#[derive(Debug, Clone, PartialEq)]
pub enum StatementType {
    Permit,
    Deny,
    Require,
    Limit,
}

/// A simple condition comparing a context field to a value.
#[derive(Debug, Clone)]
pub struct Condition {
    pub field: String,
    pub operator: String,
    pub value: String,
}

/// A CCL statement (permit, deny, require, or limit).
#[derive(Debug, Clone)]
pub struct Statement {
    pub stmt_type: StatementType,
    pub action: String,
    pub resource: String,
    pub condition: Option<Condition>,
    pub metric: Option<String>,
    pub limit: Option<f64>,
    pub period: Option<f64>,
    pub time_unit: Option<String>,
}

/// A parsed CCL document containing categorized statement arrays.
#[derive(Debug, Clone)]
pub struct CCLDocument {
    pub statements: Vec<Statement>,
    pub permits: Vec<Statement>,
    pub denies: Vec<Statement>,
    pub obligations: Vec<Statement>,
    pub limits: Vec<Statement>,
}

/// Result of evaluating a CCL document against an action/resource pair.
#[derive(Debug)]
pub struct EvaluationResult {
    pub permitted: bool,
    pub matched_rule: Option<Statement>,
    pub all_matches: Vec<Statement>,
    pub reason: String,
    pub severity: Option<String>,
}

/// Result of checking a rate limit.
pub struct RateLimitResult {
    pub exceeded: bool,
    pub remaining: i64,
    pub limit: i64,
}

/// A violation found during narrowing validation.
pub struct NarrowingViolation {
    pub message: String,
}

/// Result of validating that a child CCL only narrows the parent.
pub struct NarrowingResult {
    pub valid: bool,
    pub violations: Vec<NarrowingViolation>,
}

// ---------------------------------------------------------------------------
// Token types for the lexer
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
enum TokenType {
    Permit,
    Deny,
    Require,
    Limit,
    On,
    When,
    Severity,
    Per,
    TimeUnit, // seconds, minutes, hours, days
    Identifier,
    Number,
    StringLit,
    Operator,
    And,
    Or,
    Not,
    Dot,
    Wildcard,
    DoubleWildcard,
    LParen,
    RParen,
    LBracket,
    RBracket,
    Comma,
    Newline,
    Comment,
    Eof,
}

#[derive(Debug, Clone)]
struct Token {
    token_type: TokenType,
    value: String,
    line: usize,
    column: usize,
}

// ---------------------------------------------------------------------------
// Lexer
// ---------------------------------------------------------------------------

fn tokenize(source: &str) -> Vec<Token> {
    let chars: Vec<char> = source.chars().collect();
    let mut tokens: Vec<Token> = Vec::new();
    let mut pos = 0;
    let mut line = 1;
    let mut column = 1;

    let keywords: HashMap<&str, TokenType> = [
        ("permit", TokenType::Permit),
        ("deny", TokenType::Deny),
        ("require", TokenType::Require),
        ("limit", TokenType::Limit),
        ("on", TokenType::On),
        ("when", TokenType::When),
        ("severity", TokenType::Severity),
        ("per", TokenType::Per),
        ("seconds", TokenType::TimeUnit),
        ("second", TokenType::TimeUnit),
        ("minutes", TokenType::TimeUnit),
        ("minute", TokenType::TimeUnit),
        ("hours", TokenType::TimeUnit),
        ("hour", TokenType::TimeUnit),
        ("days", TokenType::TimeUnit),
        ("day", TokenType::TimeUnit),
        ("and", TokenType::And),
        ("or", TokenType::Or),
        ("not", TokenType::Not),
    ]
    .into_iter()
    .collect();

    let word_operators: Vec<&str> = vec![
        "contains",
        "not_contains",
        "in",
        "not_in",
        "matches",
        "starts_with",
        "ends_with",
    ];

    while pos < chars.len() {
        let ch = chars[pos];

        // Skip spaces and tabs
        if ch == ' ' || ch == '\t' || ch == '\r' {
            pos += 1;
            column += 1;
            continue;
        }

        // Newlines
        if ch == '\n' {
            let start_line = line;
            let start_col = column;
            pos += 1;
            line += 1;
            column = 1;
            if !tokens.is_empty() {
                if let Some(last) = tokens.last() {
                    if last.token_type != TokenType::Newline {
                        tokens.push(Token {
                            token_type: TokenType::Newline,
                            value: "\n".to_string(),
                            line: start_line,
                            column: start_col,
                        });
                    }
                }
            }
            continue;
        }

        // Comments: # until end of line
        if ch == '#' {
            let start_line = line;
            let start_col = column;
            let mut comment = String::new();
            while pos < chars.len() && chars[pos] != '\n' {
                comment.push(chars[pos]);
                pos += 1;
                column += 1;
            }
            tokens.push(Token {
                token_type: TokenType::Comment,
                value: comment,
                line: start_line,
                column: start_col,
            });
            continue;
        }

        // Single-quoted strings
        if ch == '\'' {
            let start_line = line;
            let start_col = column;
            pos += 1; // consume opening quote
            column += 1;
            let mut s = String::new();
            while pos < chars.len() && chars[pos] != '\'' {
                if chars[pos] == '\n' {
                    line += 1;
                    column = 0;
                }
                s.push(chars[pos]);
                pos += 1;
                column += 1;
            }
            if pos < chars.len() {
                pos += 1; // consume closing quote
                column += 1;
            }
            tokens.push(Token {
                token_type: TokenType::StringLit,
                value: s,
                line: start_line,
                column: start_col,
            });
            continue;
        }

        // Parentheses
        if ch == '(' {
            tokens.push(Token {
                token_type: TokenType::LParen,
                value: "(".to_string(),
                line,
                column,
            });
            pos += 1;
            column += 1;
            continue;
        }
        if ch == ')' {
            tokens.push(Token {
                token_type: TokenType::RParen,
                value: ")".to_string(),
                line,
                column,
            });
            pos += 1;
            column += 1;
            continue;
        }

        // Brackets
        if ch == '[' {
            tokens.push(Token {
                token_type: TokenType::LBracket,
                value: "[".to_string(),
                line,
                column,
            });
            pos += 1;
            column += 1;
            continue;
        }
        if ch == ']' {
            tokens.push(Token {
                token_type: TokenType::RBracket,
                value: "]".to_string(),
                line,
                column,
            });
            pos += 1;
            column += 1;
            continue;
        }

        // Comma
        if ch == ',' {
            tokens.push(Token {
                token_type: TokenType::Comma,
                value: ",".to_string(),
                line,
                column,
            });
            pos += 1;
            column += 1;
            continue;
        }

        // Operators: !=, <=, >=, <, >, =
        if ch == '!' && pos + 1 < chars.len() && chars[pos + 1] == '=' {
            tokens.push(Token {
                token_type: TokenType::Operator,
                value: "!=".to_string(),
                line,
                column,
            });
            pos += 2;
            column += 2;
            continue;
        }
        if ch == '<' && pos + 1 < chars.len() && chars[pos + 1] == '=' {
            tokens.push(Token {
                token_type: TokenType::Operator,
                value: "<=".to_string(),
                line,
                column,
            });
            pos += 2;
            column += 2;
            continue;
        }
        if ch == '>' && pos + 1 < chars.len() && chars[pos + 1] == '=' {
            tokens.push(Token {
                token_type: TokenType::Operator,
                value: ">=".to_string(),
                line,
                column,
            });
            pos += 2;
            column += 2;
            continue;
        }
        if ch == '<' {
            tokens.push(Token {
                token_type: TokenType::Operator,
                value: "<".to_string(),
                line,
                column,
            });
            pos += 1;
            column += 1;
            continue;
        }
        if ch == '>' {
            tokens.push(Token {
                token_type: TokenType::Operator,
                value: ">".to_string(),
                line,
                column,
            });
            pos += 1;
            column += 1;
            continue;
        }
        if ch == '=' {
            tokens.push(Token {
                token_type: TokenType::Operator,
                value: "=".to_string(),
                line,
                column,
            });
            pos += 1;
            column += 1;
            continue;
        }

        // Wildcards: ** and *
        if ch == '*' {
            let start_line = line;
            let start_col = column;
            pos += 1;
            column += 1;
            if pos < chars.len() && chars[pos] == '*' {
                pos += 1;
                column += 1;
                tokens.push(Token {
                    token_type: TokenType::DoubleWildcard,
                    value: "**".to_string(),
                    line: start_line,
                    column: start_col,
                });
            } else {
                tokens.push(Token {
                    token_type: TokenType::Wildcard,
                    value: "*".to_string(),
                    line: start_line,
                    column: start_col,
                });
            }
            continue;
        }

        // Numbers
        if ch.is_ascii_digit() {
            let start_line = line;
            let start_col = column;
            let mut num = String::new();
            while pos < chars.len() && chars[pos].is_ascii_digit() {
                num.push(chars[pos]);
                pos += 1;
                column += 1;
            }
            tokens.push(Token {
                token_type: TokenType::Number,
                value: num,
                line: start_line,
                column: start_col,
            });
            continue;
        }

        // Identifiers, keywords, and word operators
        if ch.is_ascii_alphabetic() || ch == '_' {
            let start_line = line;
            let start_col = column;
            let mut ident = String::new();
            while pos < chars.len() && (chars[pos].is_ascii_alphanumeric() || chars[pos] == '_') {
                ident.push(chars[pos]);
                pos += 1;
                column += 1;
            }

            // Check for word operators
            if word_operators.contains(&ident.as_str()) {
                tokens.push(Token {
                    token_type: TokenType::Operator,
                    value: ident,
                    line: start_line,
                    column: start_col,
                });
                continue;
            }

            // Check for keywords
            let lower = ident.to_lowercase();
            if let Some(kw) = keywords.get(lower.as_str()) {
                tokens.push(Token {
                    token_type: kw.clone(),
                    value: ident,
                    line: start_line,
                    column: start_col,
                });
                continue;
            }

            tokens.push(Token {
                token_type: TokenType::Identifier,
                value: ident,
                line: start_line,
                column: start_col,
            });
            continue;
        }

        // Dot
        if ch == '.' {
            tokens.push(Token {
                token_type: TokenType::Dot,
                value: ".".to_string(),
                line,
                column,
            });
            pos += 1;
            column += 1;
            continue;
        }

        // Forward slash (resource path)
        if ch == '/' {
            let start_line = line;
            let start_col = column;
            let mut path = String::new();
            while pos < chars.len() && !chars[pos].is_ascii_whitespace() {
                path.push(chars[pos]);
                pos += 1;
                column += 1;
            }
            tokens.push(Token {
                token_type: TokenType::StringLit,
                value: path,
                line: start_line,
                column: start_col,
            });
            continue;
        }

        // Unknown character - skip
        pos += 1;
        column += 1;
    }

    tokens.push(Token {
        token_type: TokenType::Eof,
        value: String::new(),
        line,
        column,
    });

    tokens
}

// ---------------------------------------------------------------------------
// Parser
// ---------------------------------------------------------------------------

struct Parser {
    tokens: Vec<Token>,
    pos: usize,
}

impl Parser {
    fn new(tokens: Vec<Token>) -> Self {
        Parser { tokens, pos: 0 }
    }

    fn current(&self) -> &Token {
        if self.pos < self.tokens.len() {
            &self.tokens[self.pos]
        } else {
            self.tokens.last().unwrap() // EOF token
        }
    }

    fn advance(&mut self) -> Token {
        let tok = self.current().clone();
        if self.pos < self.tokens.len() {
            self.pos += 1;
        }
        tok
    }

    fn check(&self, tt: &TokenType) -> bool {
        self.current().token_type == *tt
    }

    fn expect(&mut self, tt: &TokenType, msg: &str) -> Result<Token, KervyxError> {
        if self.current().token_type == *tt {
            Ok(self.advance())
        } else {
            Err(KervyxError::CCLParseError(format!(
                "{}, but got '{}' at line {} column {}",
                msg,
                self.current().value,
                self.current().line,
                self.current().column,
            )))
        }
    }

    fn is_at_end(&self) -> bool {
        self.current().token_type == TokenType::Eof
    }

    fn skip_newlines_and_comments(&mut self) {
        while self.pos < self.tokens.len()
            && (self.current().token_type == TokenType::Newline
                || self.current().token_type == TokenType::Comment)
        {
            self.pos += 1;
        }
    }

    fn parse(&mut self) -> Result<CCLDocument, KervyxError> {
        let mut statements = Vec::new();

        self.skip_newlines_and_comments();

        while !self.is_at_end() {
            let tt = &self.current().token_type;
            if *tt == TokenType::Newline || *tt == TokenType::Comment {
                self.advance();
                self.skip_newlines_and_comments();
                continue;
            }
            if *tt == TokenType::Eof {
                break;
            }

            let stmt = self.parse_statement()?;
            statements.push(stmt);
            self.skip_newlines_and_comments();
        }

        Ok(build_document(statements))
    }

    fn parse_statement(&mut self) -> Result<Statement, KervyxError> {
        match self.current().token_type {
            TokenType::Permit | TokenType::Deny => self.parse_permit_deny(),
            TokenType::Require => self.parse_require(),
            TokenType::Limit => self.parse_limit(),
            _ => Err(KervyxError::CCLParseError(format!(
                "Expected statement keyword (permit, deny, require, or limit), got '{}' at line {} column {}",
                self.current().value,
                self.current().line,
                self.current().column,
            ))),
        }
    }

    fn parse_permit_deny(&mut self) -> Result<Statement, KervyxError> {
        let keyword = self.advance();
        let stmt_type = if keyword.token_type == TokenType::Permit {
            StatementType::Permit
        } else {
            StatementType::Deny
        };

        let action = self.parse_action()?;
        self.expect(&TokenType::On, "Expected 'on' after action")?;
        let resource = self.parse_resource()?;

        let condition = if self.check(&TokenType::When) {
            self.advance();
            Some(self.parse_condition()?)
        } else {
            None
        };

        // Parse optional severity (ignored in simplified representation, defaults high)
        if self.check(&TokenType::Severity) {
            self.advance();
            // consume the severity level identifier
            if self.check(&TokenType::Identifier) {
                self.advance();
            }
        }

        Ok(Statement {
            stmt_type,
            action,
            resource,
            condition,
            metric: None,
            limit: None,
            period: None,
            time_unit: None,
        })
    }

    fn parse_require(&mut self) -> Result<Statement, KervyxError> {
        self.advance(); // consume 'require'
        let action = self.parse_action()?;
        self.expect(&TokenType::On, "Expected 'on' after action")?;
        let resource = self.parse_resource()?;

        let condition = if self.check(&TokenType::When) {
            self.advance();
            Some(self.parse_condition()?)
        } else {
            None
        };

        if self.check(&TokenType::Severity) {
            self.advance();
            if self.check(&TokenType::Identifier) {
                self.advance();
            }
        }

        Ok(Statement {
            stmt_type: StatementType::Require,
            action,
            resource,
            condition,
            metric: None,
            limit: None,
            period: None,
            time_unit: None,
        })
    }

    fn parse_limit(&mut self) -> Result<Statement, KervyxError> {
        self.advance(); // consume 'limit'
        let action = self.parse_action()?;

        // Parse count
        let count_tok = self.expect(&TokenType::Number, "Expected count number after action in limit statement")?;
        let count: f64 = count_tok
            .value
            .parse()
            .map_err(|_| KervyxError::CCLParseError(format!("Invalid count number: {}", count_tok.value)))?;

        self.expect(&TokenType::Per, "Expected 'per' in limit statement")?;

        // Parse period
        let period_tok = self.expect(&TokenType::Number, "Expected period number after 'per' in limit statement")?;
        let raw_period: f64 = period_tok
            .value
            .parse()
            .map_err(|_| KervyxError::CCLParseError(format!("Invalid period number: {}", period_tok.value)))?;

        // Parse time unit
        let unit_tok = self.expect(&TokenType::TimeUnit, "Expected time unit (seconds, minutes, hours, days)")?;
        let unit_value = unit_tok.value.to_lowercase();
        let multiplier = time_unit_multiplier(&unit_value);
        let period_seconds = raw_period * multiplier;

        if self.check(&TokenType::Severity) {
            self.advance();
            if self.check(&TokenType::Identifier) {
                self.advance();
            }
        }

        Ok(Statement {
            stmt_type: StatementType::Limit,
            action: action.clone(),
            resource: String::new(),
            condition: None,
            metric: Some(action),
            limit: Some(count),
            period: Some(period_seconds),
            time_unit: Some(unit_value),
        })
    }

    fn parse_action(&mut self) -> Result<String, KervyxError> {
        let mut parts = Vec::new();

        if self.check(&TokenType::DoubleWildcard) {
            self.advance();
            return Ok("**".to_string());
        }

        if self.check(&TokenType::Wildcard) {
            parts.push("*".to_string());
            self.advance();
        } else if self.check(&TokenType::Identifier) {
            parts.push(self.advance().value);
        } else {
            return Err(KervyxError::CCLParseError(format!(
                "Expected action identifier, got '{}' at line {} column {}",
                self.current().value,
                self.current().line,
                self.current().column,
            )));
        }

        while self.check(&TokenType::Dot) {
            self.advance(); // consume dot
            if self.check(&TokenType::Identifier) {
                parts.push(self.advance().value);
            } else if self.check(&TokenType::Wildcard) {
                parts.push("*".to_string());
                self.advance();
            } else if self.check(&TokenType::DoubleWildcard) {
                parts.push("**".to_string());
                self.advance();
            } else {
                return Err(KervyxError::CCLParseError(format!(
                    "Expected identifier or wildcard after dot, got '{}' at line {} column {}",
                    self.current().value,
                    self.current().line,
                    self.current().column,
                )));
            }
        }

        Ok(parts.join("."))
    }

    fn parse_resource(&mut self) -> Result<String, KervyxError> {
        match self.current().token_type {
            TokenType::StringLit => Ok(self.advance().value),
            TokenType::Wildcard => {
                self.advance();
                Ok("*".to_string())
            }
            TokenType::DoubleWildcard => {
                self.advance();
                Ok("**".to_string())
            }
            TokenType::Identifier => Ok(self.advance().value),
            _ => Err(KervyxError::CCLParseError(format!(
                "Expected resource (string or pattern), got '{}' at line {} column {}",
                self.current().value,
                self.current().line,
                self.current().column,
            ))),
        }
    }

    fn parse_condition(&mut self) -> Result<Condition, KervyxError> {
        // Parse the field
        let field = self.parse_field()?;

        // Parse the operator
        if self.current().token_type != TokenType::Operator {
            return Err(KervyxError::CCLParseError(format!(
                "Expected operator after field '{}', got '{}' at line {} column {}",
                field,
                self.current().value,
                self.current().line,
                self.current().column,
            )));
        }
        let operator = self.advance().value;

        // Parse the value
        let value = self.parse_value()?;

        Ok(Condition {
            field,
            operator,
            value,
        })
    }

    fn parse_field(&mut self) -> Result<String, KervyxError> {
        if self.current().token_type != TokenType::Identifier {
            return Err(KervyxError::CCLParseError(format!(
                "Expected field identifier, got '{}' at line {} column {}",
                self.current().value,
                self.current().line,
                self.current().column,
            )));
        }

        let mut field = self.advance().value;

        while self.check(&TokenType::Dot) {
            self.advance();
            if self.current().token_type != TokenType::Identifier {
                return Err(KervyxError::CCLParseError(format!(
                    "Expected identifier after dot in field, got '{}' at line {} column {}",
                    self.current().value,
                    self.current().line,
                    self.current().column,
                )));
            }
            field.push('.');
            field.push_str(&self.advance().value);
        }

        Ok(field)
    }

    fn parse_value(&mut self) -> Result<String, KervyxError> {
        match self.current().token_type {
            TokenType::StringLit => Ok(self.advance().value),
            TokenType::Number => Ok(self.advance().value),
            TokenType::Identifier => Ok(self.advance().value),
            _ => Err(KervyxError::CCLParseError(format!(
                "Expected value, got '{}' at line {} column {}",
                self.current().value,
                self.current().line,
                self.current().column,
            ))),
        }
    }
}

fn time_unit_multiplier(unit: &str) -> f64 {
    match unit {
        "second" | "seconds" => 1.0,
        "minute" | "minutes" => 60.0,
        "hour" | "hours" => 3600.0,
        "day" | "days" => 86400.0,
        _ => 1.0,
    }
}

fn build_document(statements: Vec<Statement>) -> CCLDocument {
    let mut permits = Vec::new();
    let mut denies = Vec::new();
    let mut obligations = Vec::new();
    let mut limits = Vec::new();

    for stmt in &statements {
        match stmt.stmt_type {
            StatementType::Permit => permits.push(stmt.clone()),
            StatementType::Deny => denies.push(stmt.clone()),
            StatementType::Require => obligations.push(stmt.clone()),
            StatementType::Limit => limits.push(stmt.clone()),
        }
    }

    CCLDocument {
        statements,
        permits,
        denies,
        obligations,
        limits,
    }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Parse CCL source text into a `CCLDocument`.
///
/// # Errors
/// Returns `KervyxError::CCLParseError` if the source contains syntax errors.
///
/// # Example
/// ```
/// use kervyx::ccl::parse;
/// let doc = parse("permit read on '/data/**'").unwrap();
/// assert_eq!(doc.permits.len(), 1);
/// ```
pub fn parse(source: &str) -> Result<CCLDocument, KervyxError> {
    let tokens = tokenize(source);
    let mut parser = Parser::new(tokens);
    parser.parse()
}

/// Match an action string against a dot-separated pattern.
///
/// Segments are split on `.`. Wildcard rules:
/// - `*` matches exactly one segment
/// - `**` matches zero or more segments
pub fn match_action(pattern: &str, action: &str) -> bool {
    let pattern_parts: Vec<&str> = pattern.split('.').collect();
    let action_parts: Vec<&str> = action.split('.').collect();
    match_segments(&pattern_parts, 0, &action_parts, 0)
}

/// Match a resource path against a slash-separated pattern.
///
/// Leading and trailing slashes are normalized. Wildcard rules:
/// - `*` matches exactly one path segment
/// - `**` matches zero or more segments
pub fn match_resource(pattern: &str, resource: &str) -> bool {
    let norm_pattern = pattern.trim_matches('/');
    let norm_resource = resource.trim_matches('/');

    if norm_pattern.is_empty() && norm_resource.is_empty() {
        return true;
    }
    if norm_pattern == "**" {
        return true;
    }
    if norm_pattern == "*" && !norm_resource.contains('/') {
        return true;
    }

    let pattern_parts: Vec<&str> = norm_pattern.split('/').collect();
    let resource_parts: Vec<&str> = norm_resource.split('/').collect();
    match_segments(&pattern_parts, 0, &resource_parts, 0)
}

/// Generic segment matcher supporting `*` (single) and `**` (multi) wildcards.
fn match_segments(pattern: &[&str], pi: usize, target: &[&str], ti: usize) -> bool {
    let mut pi = pi;
    let mut ti = ti;

    while pi < pattern.len() && ti < target.len() {
        let p = pattern[pi];

        if p == "**" {
            // ** can match zero or more segments
            if match_segments(pattern, pi + 1, target, ti) {
                return true;
            }
            return match_segments(pattern, pi, target, ti + 1);
        }

        if p == "*" {
            // * matches exactly one segment
            pi += 1;
            ti += 1;
            continue;
        }

        // Literal match
        if p != target[ti] {
            return false;
        }
        pi += 1;
        ti += 1;
    }

    // Skip trailing ** patterns
    while pi < pattern.len() && pattern[pi] == "**" {
        pi += 1;
    }

    pi == pattern.len() && ti == target.len()
}

/// Calculate the specificity score of an action+resource pattern pair.
///
/// Scoring per segment: literal = 2, `*` = 1, `**` = 0.
fn specificity(action_pattern: &str, resource_pattern: &str) -> i32 {
    let mut score = 0i32;

    for part in action_pattern.split('.') {
        match part {
            "**" => {}
            "*" => score += 1,
            _ => score += 2,
        }
    }

    let norm_resource = resource_pattern.trim_matches('/');
    if !norm_resource.is_empty() {
        for part in norm_resource.split('/') {
            match part {
                "**" => {}
                "*" => score += 1,
                _ => score += 2,
            }
        }
    }

    score
}

/// Evaluate a condition against a context map.
fn evaluate_condition(condition: &Condition, context: &HashMap<String, String>) -> bool {
    let field_value = match context.get(&condition.field) {
        Some(v) => v.clone(),
        None => return false,
    };

    match condition.operator.as_str() {
        "=" => field_value == condition.value,
        "!=" => field_value != condition.value,
        "<" => {
            if let (Ok(a), Ok(b)) = (field_value.parse::<f64>(), condition.value.parse::<f64>()) {
                a < b
            } else {
                false
            }
        }
        ">" => {
            if let (Ok(a), Ok(b)) = (field_value.parse::<f64>(), condition.value.parse::<f64>()) {
                a > b
            } else {
                false
            }
        }
        "<=" => {
            if let (Ok(a), Ok(b)) = (field_value.parse::<f64>(), condition.value.parse::<f64>()) {
                a <= b
            } else {
                false
            }
        }
        ">=" => {
            if let (Ok(a), Ok(b)) = (field_value.parse::<f64>(), condition.value.parse::<f64>()) {
                a >= b
            } else {
                false
            }
        }
        "contains" => field_value.contains(&condition.value),
        "not_contains" => !field_value.contains(&condition.value),
        "starts_with" => field_value.starts_with(&condition.value),
        "ends_with" => field_value.ends_with(&condition.value),
        "matches" => {
            // Simple prefix/suffix matching since we don't pull in regex
            field_value == condition.value
        }
        _ => false,
    }
}

/// Evaluate a CCL document against an action/resource pair.
///
/// Resolution order:
/// 1. Find all matching statements (action + resource match, conditions pass)
/// 2. Sort by specificity (most specific first)
/// 3. At equal specificity, deny wins over permit
/// 4. If no rules match, default is deny (`permitted: false`)
pub fn evaluate(
    doc: &CCLDocument,
    action: &str,
    resource: &str,
    context: &HashMap<String, String>,
) -> EvaluationResult {
    let mut all_matches: Vec<Statement> = Vec::new();
    let mut matched_permit_deny: Vec<Statement> = Vec::new();

    // Collect matching permits
    for stmt in &doc.permits {
        if match_action(&stmt.action, action) && match_resource(&stmt.resource, resource) {
            if stmt.condition.is_none()
                || stmt
                    .condition
                    .as_ref()
                    .map_or(true, |c| evaluate_condition(c, context))
            {
                matched_permit_deny.push(stmt.clone());
                all_matches.push(stmt.clone());
            }
        }
    }

    // Collect matching denies
    for stmt in &doc.denies {
        if match_action(&stmt.action, action) && match_resource(&stmt.resource, resource) {
            if stmt.condition.is_none()
                || stmt
                    .condition
                    .as_ref()
                    .map_or(true, |c| evaluate_condition(c, context))
            {
                matched_permit_deny.push(stmt.clone());
                all_matches.push(stmt.clone());
            }
        }
    }

    // Collect matching obligations (don't affect permit/deny)
    for stmt in &doc.obligations {
        if match_action(&stmt.action, action) && match_resource(&stmt.resource, resource) {
            if stmt.condition.is_none()
                || stmt
                    .condition
                    .as_ref()
                    .map_or(true, |c| evaluate_condition(c, context))
            {
                all_matches.push(stmt.clone());
            }
        }
    }

    // No matching permit/deny rules: default deny
    if matched_permit_deny.is_empty() {
        return EvaluationResult {
            permitted: false,
            matched_rule: None,
            all_matches,
            reason: "No matching rules found; default deny".to_string(),
            severity: None,
        };
    }

    // Sort by specificity descending; at equal specificity, deny wins
    matched_permit_deny.sort_by(|a, b| {
        let spec_a = specificity(&a.action, &a.resource);
        let spec_b = specificity(&b.action, &b.resource);

        match spec_b.cmp(&spec_a) {
            std::cmp::Ordering::Equal => {
                // At equal specificity, deny wins
                let a_is_deny = a.stmt_type == StatementType::Deny;
                let b_is_deny = b.stmt_type == StatementType::Deny;
                match (a_is_deny, b_is_deny) {
                    (true, false) => std::cmp::Ordering::Less,
                    (false, true) => std::cmp::Ordering::Greater,
                    _ => std::cmp::Ordering::Equal,
                }
            }
            other => other,
        }
    });

    let winner = &matched_permit_deny[0];
    let permitted = winner.stmt_type == StatementType::Permit;

    EvaluationResult {
        permitted,
        matched_rule: Some(winner.clone()),
        all_matches,
        reason: format!(
            "Matched {:?} rule for {} on {}",
            winner.stmt_type, winner.action, winner.resource
        ),
        severity: None,
    }
}

/// Check whether an action has exceeded its rate limit.
///
/// Finds the most specific matching limit statement, then checks whether
/// `current_count` exceeds the allowed count within the time window.
pub fn check_rate_limit(
    doc: &CCLDocument,
    metric: &str,
    current_count: i64,
    window_start_ms: i64,
    now_ms: i64,
) -> RateLimitResult {
    let mut matched_limit: Option<&Statement> = None;
    let mut best_specificity = -1i32;

    for limit_stmt in &doc.limits {
        if match_action(&limit_stmt.action, metric) {
            let spec = specificity(&limit_stmt.action, "");
            if spec > best_specificity {
                best_specificity = spec;
                matched_limit = Some(limit_stmt);
            }
        }
    }

    let limit_stmt = match matched_limit {
        Some(s) => s,
        None => {
            return RateLimitResult {
                exceeded: false,
                remaining: i64::MAX,
                limit: 0,
            }
        }
    };

    let count_limit = limit_stmt.limit.unwrap_or(0.0) as i64;
    let period_seconds = limit_stmt.period.unwrap_or(0.0);
    let period_ms = (period_seconds * 1000.0) as i64;
    let elapsed = now_ms - window_start_ms;

    if elapsed > period_ms {
        // Period has expired; the count resets
        return RateLimitResult {
            exceeded: false,
            remaining: count_limit,
            limit: count_limit,
        };
    }

    let remaining = (count_limit - current_count).max(0);
    RateLimitResult {
        exceeded: current_count >= count_limit,
        remaining,
        limit: count_limit,
    }
}

/// Validate that a child CCL document only narrows (restricts) the parent.
///
/// Violations occur when:
/// - A child permits something the parent explicitly denies
/// - A child permit covers a broader scope than any parent permit
pub fn validate_narrowing(parent: &CCLDocument, child: &CCLDocument) -> NarrowingResult {
    let mut violations = Vec::new();

    for child_permit in &child.permits {
        // Check against parent denies
        for parent_deny in &parent.denies {
            if patterns_overlap(&child_permit.action, &parent_deny.action)
                && patterns_overlap(&child_permit.resource, &parent_deny.resource)
            {
                violations.push(NarrowingViolation {
                    message: format!(
                        "Child permits '{}' on '{}' which parent denies",
                        child_permit.action, child_permit.resource
                    ),
                });
            }
        }

        // Check if child permit is broader than any parent permit
        if !parent.permits.is_empty() {
            let has_matching_parent = parent.permits.iter().any(|parent_permit| {
                is_subset_pattern(&child_permit.action, &parent_permit.action, ".")
                    && is_subset_pattern(&child_permit.resource, &parent_permit.resource, "/")
            });

            if !has_matching_parent {
                violations.push(NarrowingViolation {
                    message: format!(
                        "Child permit '{}' on '{}' is not a subset of any parent permit",
                        child_permit.action, child_permit.resource
                    ),
                });
            }
        }
    }

    NarrowingResult {
        valid: violations.is_empty(),
        violations,
    }
}

/// Check if two patterns can match any of the same strings.
fn patterns_overlap(pattern1: &str, pattern2: &str) -> bool {
    if pattern1 == "**" || pattern2 == "**" {
        return true;
    }
    if pattern1 == "*" || pattern2 == "*" {
        return true;
    }
    if pattern1 == pattern2 {
        return true;
    }

    let concrete1 = pattern_to_concrete(pattern1);
    let concrete2 = pattern_to_concrete(pattern2);

    if pattern1.contains('/') || pattern2.contains('/') {
        match_resource(pattern1, &concrete2) || match_resource(pattern2, &concrete1)
    } else {
        match_action(pattern1, &concrete2) || match_action(pattern2, &concrete1)
    }
}

fn pattern_to_concrete(pattern: &str) -> String {
    pattern.replace("**", "x").replace('*', "x")
}

/// Check if child_pattern is a subset of (at most as broad as) parent_pattern.
fn is_subset_pattern(child_pattern: &str, parent_pattern: &str, separator: &str) -> bool {
    if parent_pattern == "**" {
        return true;
    }
    if child_pattern == "**" && parent_pattern != "**" {
        return false;
    }

    let child_parts: Vec<&str> = child_pattern
        .split(separator)
        .filter(|p| !p.is_empty())
        .collect();
    let parent_parts: Vec<&str> = parent_pattern
        .split(separator)
        .filter(|p| !p.is_empty())
        .collect();

    is_subset_segments(&child_parts, 0, &parent_parts, 0)
}

fn is_subset_segments(child: &[&str], ci: usize, parent: &[&str], pi: usize) -> bool {
    if ci == child.len() && pi == parent.len() {
        return true;
    }
    if pi == parent.len() {
        return false;
    }
    if ci == child.len() {
        // Only ok if remaining parent segments are all **
        for i in pi..parent.len() {
            if parent[i] != "**" {
                return false;
            }
        }
        return true;
    }

    let p_seg = parent[pi];
    let c_seg = child[ci];

    if p_seg == "**" {
        if is_subset_segments(child, ci, parent, pi + 1) {
            return true;
        }
        return is_subset_segments(child, ci + 1, parent, pi);
    }

    if c_seg == "**" {
        // Child ** is broader than parent non-**
        if p_seg != "**" {
            return false;
        }
        return is_subset_segments(child, ci + 1, parent, pi + 1);
    }

    if p_seg == "*" {
        // Parent * matches one segment; child can be * or literal (narrower)
        return is_subset_segments(child, ci + 1, parent, pi + 1);
    }

    if c_seg == "*" {
        // Child * is broader than a literal parent
        if p_seg != "*" && p_seg != "**" {
            return false;
        }
        return is_subset_segments(child, ci + 1, parent, pi + 1);
    }

    // Both literals: must match exactly
    if c_seg != p_seg {
        return false;
    }
    is_subset_segments(child, ci + 1, parent, pi + 1)
}

/// Merge a parent and child CCL document with deny-wins semantics.
///
/// - All denies from both parent and child are included.
/// - All permits from both are included.
/// - All obligations from both are included.
/// - For limits on the same action, the more restrictive (lower count) wins.
pub fn merge(parent: &CCLDocument, child: &CCLDocument) -> CCLDocument {
    let mut statements: Vec<Statement> = Vec::new();

    // All denies from both
    statements.extend(parent.denies.clone());
    statements.extend(child.denies.clone());

    // All permits from both
    statements.extend(child.permits.clone());
    statements.extend(parent.permits.clone());

    // All obligations from both
    statements.extend(parent.obligations.clone());
    statements.extend(child.obligations.clone());

    // Limits: take the more restrictive if both specify for same action
    let mut limits_by_action: HashMap<String, Statement> = HashMap::new();
    for limit in parent.limits.iter().chain(child.limits.iter()) {
        let action = &limit.action;
        let count = limit.limit.unwrap_or(f64::MAX);
        if let Some(existing) = limits_by_action.get(action) {
            if count < existing.limit.unwrap_or(f64::MAX) {
                limits_by_action.insert(action.clone(), limit.clone());
            }
        } else {
            limits_by_action.insert(action.clone(), limit.clone());
        }
    }
    statements.extend(limits_by_action.into_values());

    build_document(statements)
}

/// Serialize a CCL document back to human-readable CCL source text.
pub fn serialize(doc: &CCLDocument) -> String {
    let mut lines = Vec::new();

    for stmt in &doc.statements {
        lines.push(serialize_statement(stmt));
    }

    lines.join("\n")
}

fn serialize_statement(stmt: &Statement) -> String {
    match stmt.stmt_type {
        StatementType::Permit => {
            let mut line = format!("permit {} on '{}'", stmt.action, stmt.resource);
            if let Some(ref cond) = stmt.condition {
                line.push_str(&format!(" when {} {} '{}'", cond.field, cond.operator, cond.value));
            }
            line
        }
        StatementType::Deny => {
            let mut line = format!("deny {} on '{}'", stmt.action, stmt.resource);
            if let Some(ref cond) = stmt.condition {
                line.push_str(&format!(" when {} {} '{}'", cond.field, cond.operator, cond.value));
            }
            line
        }
        StatementType::Require => {
            let mut line = format!("require {} on '{}'", stmt.action, stmt.resource);
            if let Some(ref cond) = stmt.condition {
                line.push_str(&format!(" when {} {} '{}'", cond.field, cond.operator, cond.value));
            }
            line
        }
        StatementType::Limit => {
            let count = stmt.limit.unwrap_or(0.0) as i64;
            let period_seconds = stmt.period.unwrap_or(0.0);
            let (period_val, unit) = best_time_unit(period_seconds);
            format!("limit {} {} per {} {}", stmt.action, count, period_val, unit)
        }
    }
}

fn best_time_unit(seconds: f64) -> (i64, &'static str) {
    let s = seconds as i64;
    if s > 0 && s % 86400 == 0 {
        (s / 86400, "days")
    } else if s > 0 && s % 3600 == 0 {
        (s / 3600, "hours")
    } else if s > 0 && s % 60 == 0 {
        (s / 60, "minutes")
    } else {
        (s, "seconds")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_permit() {
        let doc = parse("permit read on '/data/**'").unwrap();
        assert_eq!(doc.permits.len(), 1);
        assert_eq!(doc.permits[0].action, "read");
        assert_eq!(doc.permits[0].resource, "/data/**");
    }

    #[test]
    fn test_parse_deny() {
        let doc = parse("deny write on '/secret'").unwrap();
        assert_eq!(doc.denies.len(), 1);
        assert_eq!(doc.denies[0].action, "write");
    }

    #[test]
    fn test_parse_limit() {
        let doc = parse("limit api.call 100 per 1 hours").unwrap();
        assert_eq!(doc.limits.len(), 1);
        assert_eq!(doc.limits[0].limit, Some(100.0));
        assert_eq!(doc.limits[0].period, Some(3600.0));
    }

    #[test]
    fn test_match_action() {
        assert!(match_action("file.*", "file.read"));
        assert!(!match_action("file.*", "file.a.b"));
        assert!(match_action("**", "anything.here"));
        assert!(match_action("file.**", "file.read.all"));
    }

    #[test]
    fn test_match_resource() {
        assert!(match_resource("/data/**", "/data/users/123"));
        assert!(!match_resource("/data/*", "/data/users/123"));
        assert!(match_resource("/data/*", "/data/users"));
    }

    #[test]
    fn test_evaluate_default_deny() {
        let doc = parse("permit read on '/allowed'").unwrap();
        let ctx = HashMap::new();
        let result = evaluate(&doc, "write", "/allowed", &ctx);
        assert!(!result.permitted);
    }

    #[test]
    fn test_evaluate_permit() {
        let doc = parse("permit read on '/data/**'").unwrap();
        let ctx = HashMap::new();
        let result = evaluate(&doc, "read", "/data/users", &ctx);
        assert!(result.permitted);
    }

    #[test]
    fn test_evaluate_deny_wins() {
        let doc = parse("permit read on '/data/**'\ndeny read on '/data/secret'").unwrap();
        let ctx = HashMap::new();
        let result = evaluate(&doc, "read", "/data/secret", &ctx);
        assert!(!result.permitted);
    }

    #[test]
    fn test_serialize_roundtrip() {
        let source = "permit read on '/data/**'";
        let doc = parse(source).unwrap();
        let serialized = serialize(&doc);
        assert!(serialized.contains("permit"));
        assert!(serialized.contains("read"));
    }
}
