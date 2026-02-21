package grith

import (
	"encoding/json"
	"fmt"
	"math"
	"strconv"
	"strings"
	"unicode"
)

// StatementType represents the four CCL statement types.
type StatementType string

const (
	StatementPermit  StatementType = "permit"
	StatementDeny    StatementType = "deny"
	StatementRequire StatementType = "require"
	StatementLimit   StatementType = "limit"
)

// Condition represents a simple comparison in a when clause.
type Condition struct {
	Field    string
	Operator string
	Value    string
}

// Statement represents a single CCL statement.
type Statement struct {
	Type      StatementType
	Action    string
	Resource  string
	Condition *Condition
	// For limit statements:
	Metric   string  // the action being rate-limited
	Limit    float64 // max count allowed
	Period   float64 // period in milliseconds
	TimeUnit string  // original time unit string
}

// CCLDocument is a parsed CCL document with categorized statement arrays.
type CCLDocument struct {
	Statements  []Statement
	Permits     []Statement
	Denies      []Statement
	Obligations []Statement
	Limits      []Statement
}

// EvaluationResult is the result of evaluating a CCL document against
// an action/resource pair.
type EvaluationResult struct {
	Permitted   bool
	MatchedRule *Statement
	AllMatches  []Statement
	Reason      string
	Severity    string
}

// RateLimitResult is the result of checking a rate limit.
type RateLimitResult struct {
	Exceeded  bool
	Remaining int
	Limit     int
}

// NarrowingViolation describes a single violation of constraint narrowing.
type NarrowingViolation struct {
	Message string
	Child   *Statement
	Parent  *Statement
}

// NarrowingResult is the result of validating that a child CCL document
// only narrows the parent's constraints.
type NarrowingResult struct {
	Valid      bool
	Violations []NarrowingViolation
}

// ----------------------------------------------------------------------------
// Tokenizer
// ----------------------------------------------------------------------------

type tokenType int

const (
	tokEOF tokenType = iota
	tokNewline
	tokComment
	tokPermit
	tokDeny
	tokRequire
	tokLimitKw
	tokOn
	tokWhen
	tokPer
	tokTimeUnit
	tokIdentifier
	tokNumber
	tokString
	tokOperator
	tokWildcard
	tokDoubleWildcard
	tokDot
)

type token struct {
	typ    tokenType
	value  string
	line   int
	column int
}

func tokenize(source string) []token {
	var tokens []token
	runes := []rune(source)
	pos := 0
	line := 1
	col := 1

	peek := func() rune {
		if pos < len(runes) {
			return runes[pos]
		}
		return 0
	}

	peekAt := func(offset int) rune {
		idx := pos + offset
		if idx < len(runes) {
			return runes[idx]
		}
		return 0
	}

	advance := func() rune {
		ch := runes[pos]
		pos++
		col++
		return ch
	}

	addToken := func(t tokenType, val string, ln, c int) {
		tokens = append(tokens, token{typ: t, value: val, line: ln, column: c})
	}

	// Time unit keywords
	timeUnits := map[string]bool{
		"seconds": true, "second": true,
		"minutes": true, "minute": true,
		"hours": true, "hour": true,
		"days": true, "day": true,
	}

	keywords := map[string]tokenType{
		"permit":  tokPermit,
		"deny":    tokDeny,
		"require": tokRequire,
		"limit":   tokLimitKw,
		"on":      tokOn,
		"when":    tokWhen,
		"per":     tokPer,
	}

	for pos < len(runes) {
		ch := peek()

		// Skip spaces and tabs
		if ch == ' ' || ch == '\t' || ch == '\r' {
			advance()
			continue
		}

		// Newlines
		if ch == '\n' {
			startLine := line
			startCol := col
			advance()
			line++
			col = 1
			if len(tokens) > 0 && tokens[len(tokens)-1].typ != tokNewline {
				addToken(tokNewline, "\n", startLine, startCol)
			}
			continue
		}

		// Comments
		if ch == '#' {
			startLine := line
			startCol := col
			var comment strings.Builder
			for pos < len(runes) && peek() != '\n' {
				comment.WriteRune(advance())
			}
			addToken(tokComment, comment.String(), startLine, startCol)
			continue
		}

		// Single-quoted strings
		if ch == '\'' {
			startLine := line
			startCol := col
			advance() // consume opening quote
			var str strings.Builder
			for pos < len(runes) && peek() != '\'' {
				if peek() == '\n' {
					line++
					col = 0
				}
				str.WriteRune(advance())
			}
			if pos < len(runes) {
				advance() // consume closing quote
			}
			addToken(tokString, str.String(), startLine, startCol)
			continue
		}

		// Operators: !=, <=, >=, <, >, =
		if ch == '!' && peekAt(1) == '=' {
			startCol := col
			advance()
			advance()
			addToken(tokOperator, "!=", line, startCol)
			continue
		}
		if ch == '<' && peekAt(1) == '=' {
			startCol := col
			advance()
			advance()
			addToken(tokOperator, "<=", line, startCol)
			continue
		}
		if ch == '>' && peekAt(1) == '=' {
			startCol := col
			advance()
			advance()
			addToken(tokOperator, ">=", line, startCol)
			continue
		}
		if ch == '<' {
			addToken(tokOperator, "<", line, col)
			advance()
			continue
		}
		if ch == '>' {
			addToken(tokOperator, ">", line, col)
			advance()
			continue
		}
		if ch == '=' {
			addToken(tokOperator, "=", line, col)
			advance()
			continue
		}

		// Wildcards: ** and *
		if ch == '*' {
			startLine := line
			startCol := col
			advance()
			if pos < len(runes) && peek() == '*' {
				advance()
				addToken(tokDoubleWildcard, "**", startLine, startCol)
			} else {
				addToken(tokWildcard, "*", startLine, startCol)
			}
			continue
		}

		// Numbers
		if ch >= '0' && ch <= '9' {
			startLine := line
			startCol := col
			var num strings.Builder
			for pos < len(runes) && peek() >= '0' && peek() <= '9' {
				num.WriteRune(advance())
			}
			// Check for decimal numbers
			if pos < len(runes) && peek() == '.' {
				num.WriteRune(advance())
				for pos < len(runes) && peek() >= '0' && peek() <= '9' {
					num.WriteRune(advance())
				}
			}
			addToken(tokNumber, num.String(), startLine, startCol)
			continue
		}

		// Identifiers and keywords
		if isIdentStart(ch) {
			startLine := line
			startCol := col
			var ident strings.Builder
			for pos < len(runes) && isIdentPart(peek()) {
				ident.WriteRune(advance())
			}
			word := ident.String()
			lower := strings.ToLower(word)

			if kwType, ok := keywords[lower]; ok {
				addToken(kwType, word, startLine, startCol)
			} else if timeUnits[lower] {
				addToken(tokTimeUnit, word, startLine, startCol)
			} else {
				addToken(tokIdentifier, word, startLine, startCol)
			}
			continue
		}

		// Dot
		if ch == '.' {
			addToken(tokDot, ".", line, col)
			advance()
			continue
		}

		// Forward slash: collect as resource path
		if ch == '/' {
			startLine := line
			startCol := col
			var path strings.Builder
			for pos < len(runes) && !isWhitespace(peek()) && peek() != '\n' {
				path.WriteRune(advance())
			}
			addToken(tokString, path.String(), startLine, startCol)
			continue
		}

		// Unknown character: skip
		advance()
	}

	addToken(tokEOF, "", line, col)
	return tokens
}

func isIdentStart(ch rune) bool {
	return unicode.IsLetter(ch) || ch == '_'
}

func isIdentPart(ch rune) bool {
	return unicode.IsLetter(ch) || unicode.IsDigit(ch) || ch == '_'
}

func isWhitespace(ch rune) bool {
	return ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n'
}

// ----------------------------------------------------------------------------
// Parser
// ----------------------------------------------------------------------------

type parser struct {
	tokens []token
	pos    int
}

func newParser(tokens []token) *parser {
	return &parser{tokens: tokens, pos: 0}
}

func (p *parser) current() token {
	if p.pos >= len(p.tokens) {
		return token{typ: tokEOF, value: ""}
	}
	return p.tokens[p.pos]
}

func (p *parser) advance() token {
	tok := p.current()
	if p.pos < len(p.tokens) {
		p.pos++
	}
	return tok
}

func (p *parser) check(t tokenType) bool {
	return p.current().typ == t
}

func (p *parser) expect(t tokenType, msg string) (token, error) {
	tok := p.current()
	if tok.typ != t {
		return tok, fmt.Errorf("CCL parse error at line %d, col %d: %s, got '%s'", tok.line, tok.column, msg, tok.value)
	}
	return p.advance(), nil
}

func (p *parser) isAtEnd() bool {
	return p.current().typ == tokEOF
}

func (p *parser) skipNewlinesAndComments() {
	for p.pos < len(p.tokens) && (p.current().typ == tokNewline || p.current().typ == tokComment) {
		p.pos++
	}
}

// Parse parses a CCL source string into a CCLDocument.
func Parse(source string) (*CCLDocument, error) {
	tokens := tokenize(source)
	p := newParser(tokens)
	return p.parse()
}

func (p *parser) parse() (*CCLDocument, error) {
	var statements []Statement

	p.skipNewlinesAndComments()

	for !p.isAtEnd() {
		tok := p.current()

		if tok.typ == tokNewline || tok.typ == tokComment {
			p.advance()
			p.skipNewlinesAndComments()
			continue
		}

		if tok.typ == tokEOF {
			break
		}

		stmt, err := p.parseStatement()
		if err != nil {
			return nil, err
		}
		statements = append(statements, stmt)
		p.skipNewlinesAndComments()
	}

	return buildCCLDocument(statements), nil
}

func (p *parser) parseStatement() (Statement, error) {
	tok := p.current()

	switch tok.typ {
	case tokPermit:
		return p.parsePermitDeny()
	case tokDeny:
		return p.parsePermitDeny()
	case tokRequire:
		return p.parseRequireStmt()
	case tokLimitKw:
		return p.parseLimitStmt()
	default:
		return Statement{}, fmt.Errorf("CCL parse error at line %d, col %d: expected statement keyword (permit, deny, require, limit), got '%s'", tok.line, tok.column, tok.value)
	}
}

func (p *parser) parsePermitDeny() (Statement, error) {
	keyword := p.advance()
	stmtType := StatementPermit
	if strings.ToLower(keyword.value) == "deny" {
		stmtType = StatementDeny
	}

	action, err := p.parseAction()
	if err != nil {
		return Statement{}, err
	}

	if _, err := p.expect(tokOn, "expected 'on' after action"); err != nil {
		return Statement{}, err
	}

	resource, err := p.parseResource()
	if err != nil {
		return Statement{}, err
	}

	var cond *Condition
	if p.check(tokWhen) {
		p.advance()
		c, err := p.parseCondition()
		if err != nil {
			return Statement{}, err
		}
		cond = c
	}

	return Statement{
		Type:      stmtType,
		Action:    action,
		Resource:  resource,
		Condition: cond,
	}, nil
}

func (p *parser) parseRequireStmt() (Statement, error) {
	p.advance() // consume 'require'

	action, err := p.parseAction()
	if err != nil {
		return Statement{}, err
	}

	if _, err := p.expect(tokOn, "expected 'on' after action"); err != nil {
		return Statement{}, err
	}

	resource, err := p.parseResource()
	if err != nil {
		return Statement{}, err
	}

	var cond *Condition
	if p.check(tokWhen) {
		p.advance()
		c, err := p.parseCondition()
		if err != nil {
			return Statement{}, err
		}
		cond = c
	}

	return Statement{
		Type:      StatementRequire,
		Action:    action,
		Resource:  resource,
		Condition: cond,
	}, nil
}

func (p *parser) parseLimitStmt() (Statement, error) {
	p.advance() // consume 'limit'

	action, err := p.parseAction()
	if err != nil {
		return Statement{}, err
	}

	// Parse count
	countTok := p.current()
	if countTok.typ != tokNumber {
		return Statement{}, fmt.Errorf("CCL parse error at line %d, col %d: expected count number after action in limit statement, got '%s'", countTok.line, countTok.column, countTok.value)
	}
	count, err := strconv.ParseFloat(countTok.value, 64)
	if err != nil {
		return Statement{}, fmt.Errorf("CCL parse error: invalid count number '%s'", countTok.value)
	}
	p.advance()

	// Expect 'per'
	if _, err := p.expect(tokPer, "expected 'per' in limit statement"); err != nil {
		return Statement{}, err
	}

	// Parse period number
	periodTok := p.current()
	if periodTok.typ != tokNumber {
		return Statement{}, fmt.Errorf("CCL parse error at line %d, col %d: expected period number after 'per', got '%s'", periodTok.line, periodTok.column, periodTok.value)
	}
	rawPeriod, err := strconv.ParseFloat(periodTok.value, 64)
	if err != nil {
		return Statement{}, fmt.Errorf("CCL parse error: invalid period number '%s'", periodTok.value)
	}
	p.advance()

	// Parse time unit
	unitTok := p.current()
	if unitTok.typ != tokTimeUnit {
		return Statement{}, fmt.Errorf("CCL parse error at line %d, col %d: expected time unit (seconds, minutes, hours, days), got '%s'", unitTok.line, unitTok.column, unitTok.value)
	}
	timeUnit := unitTok.value
	multiplier := timeUnitToMs(timeUnit)
	p.advance()

	periodMs := rawPeriod * multiplier

	return Statement{
		Type:     StatementLimit,
		Action:   action,
		Metric:   action,
		Limit:    count,
		Period:   periodMs,
		TimeUnit: timeUnit,
	}, nil
}

func timeUnitToMs(unit string) float64 {
	switch strings.ToLower(unit) {
	case "second", "seconds":
		return 1000
	case "minute", "minutes":
		return 60_000
	case "hour", "hours":
		return 3_600_000
	case "day", "days":
		return 86_400_000
	default:
		return 1000
	}
}

func (p *parser) parseAction() (string, error) {
	tok := p.current()

	if tok.typ == tokDoubleWildcard {
		p.advance()
		return "**", nil
	}

	var parts []string

	if tok.typ == tokWildcard {
		parts = append(parts, "*")
		p.advance()
	} else if tok.typ == tokIdentifier {
		parts = append(parts, tok.value)
		p.advance()
	} else {
		return "", fmt.Errorf("CCL parse error at line %d, col %d: expected action identifier, got '%s'", tok.line, tok.column, tok.value)
	}

	for p.check(tokDot) {
		p.advance() // consume dot
		next := p.current()
		if next.typ == tokIdentifier {
			parts = append(parts, next.value)
			p.advance()
		} else if next.typ == tokWildcard {
			parts = append(parts, "*")
			p.advance()
		} else if next.typ == tokDoubleWildcard {
			parts = append(parts, "**")
			p.advance()
		} else {
			return "", fmt.Errorf("CCL parse error at line %d, col %d: expected identifier or wildcard after dot, got '%s'", next.line, next.column, next.value)
		}
	}

	return strings.Join(parts, "."), nil
}

func (p *parser) parseResource() (string, error) {
	tok := p.current()

	if tok.typ == tokString {
		p.advance()
		return tok.value, nil
	}
	if tok.typ == tokWildcard {
		p.advance()
		return "*", nil
	}
	if tok.typ == tokDoubleWildcard {
		p.advance()
		return "**", nil
	}
	if tok.typ == tokIdentifier {
		p.advance()
		return tok.value, nil
	}

	return "", fmt.Errorf("CCL parse error at line %d, col %d: expected resource, got '%s'", tok.line, tok.column, tok.value)
}

func (p *parser) parseCondition() (*Condition, error) {
	// Parse field
	fieldTok := p.current()
	if fieldTok.typ != tokIdentifier {
		return nil, fmt.Errorf("CCL parse error at line %d, col %d: expected field identifier in condition, got '%s'", fieldTok.line, fieldTok.column, fieldTok.value)
	}
	field := fieldTok.value
	p.advance()

	// Handle dotted field names
	for p.check(tokDot) {
		p.advance()
		next := p.current()
		if next.typ != tokIdentifier {
			return nil, fmt.Errorf("CCL parse error at line %d, col %d: expected identifier after dot in field, got '%s'", next.line, next.column, next.value)
		}
		field += "." + next.value
		p.advance()
	}

	// Parse operator
	opTok := p.current()
	if opTok.typ != tokOperator {
		return nil, fmt.Errorf("CCL parse error at line %d, col %d: expected operator, got '%s'", opTok.line, opTok.column, opTok.value)
	}
	op := opTok.value
	p.advance()

	// Parse value
	valTok := p.current()
	var value string
	switch valTok.typ {
	case tokString:
		value = valTok.value
		p.advance()
	case tokNumber:
		value = valTok.value
		p.advance()
	case tokIdentifier:
		value = valTok.value
		p.advance()
	default:
		return nil, fmt.Errorf("CCL parse error at line %d, col %d: expected value, got '%s'", valTok.line, valTok.column, valTok.value)
	}

	return &Condition{
		Field:    field,
		Operator: op,
		Value:    value,
	}, nil
}

func buildCCLDocument(statements []Statement) *CCLDocument {
	doc := &CCLDocument{
		Statements: statements,
	}
	for i := range statements {
		switch statements[i].Type {
		case StatementPermit:
			doc.Permits = append(doc.Permits, statements[i])
		case StatementDeny:
			doc.Denies = append(doc.Denies, statements[i])
		case StatementRequire:
			doc.Obligations = append(doc.Obligations, statements[i])
		case StatementLimit:
			doc.Limits = append(doc.Limits, statements[i])
		}
	}
	return doc
}

// ----------------------------------------------------------------------------
// Evaluation
// ----------------------------------------------------------------------------

// MatchAction tests whether a concrete action matches a dot-separated pattern.
// Wildcards: * matches one segment, ** matches zero or more segments.
func MatchAction(pattern, action string) bool {
	patternParts := strings.Split(pattern, ".")
	actionParts := strings.Split(action, ".")
	return matchSegments(patternParts, 0, actionParts, 0)
}

// MatchResource tests whether a concrete resource matches a slash-separated pattern.
// Leading and trailing slashes are normalized. Wildcards: * matches one segment,
// ** matches zero or more segments.
func MatchResource(pattern, resource string) bool {
	normPattern := strings.Trim(pattern, "/")
	normResource := strings.Trim(resource, "/")

	if normPattern == "" && normResource == "" {
		return true
	}
	if normPattern == "**" {
		return true
	}
	if normPattern == "*" && !strings.Contains(normResource, "/") {
		return true
	}

	patternParts := strings.Split(normPattern, "/")
	resourceParts := strings.Split(normResource, "/")
	return matchSegments(patternParts, 0, resourceParts, 0)
}

func matchSegments(pattern []string, pi int, target []string, ti int) bool {
	for pi < len(pattern) && ti < len(target) {
		p := pattern[pi]

		if p == "**" {
			// ** can match zero or more segments
			if matchSegments(pattern, pi+1, target, ti) {
				return true
			}
			return matchSegments(pattern, pi, target, ti+1)
		}

		if p == "*" {
			pi++
			ti++
			continue
		}

		// Literal match
		if p != target[ti] {
			return false
		}
		pi++
		ti++
	}

	// Skip trailing ** patterns
	for pi < len(pattern) && pattern[pi] == "**" {
		pi++
	}

	return pi == len(pattern) && ti == len(target)
}

// specificity computes a specificity score for a pattern pair.
// Literal segments score 2, * scores 1, ** scores 0.
func specificity(actionPattern, resourcePattern string) int {
	score := 0

	for _, part := range strings.Split(actionPattern, ".") {
		switch part {
		case "**":
			score += 0
		case "*":
			score += 1
		default:
			score += 2
		}
	}

	normResource := strings.Trim(resourcePattern, "/")
	if normResource != "" {
		for _, part := range strings.Split(normResource, "/") {
			switch part {
			case "**":
				score += 0
			case "*":
				score += 1
			default:
				score += 2
			}
		}
	}

	return score
}

// evaluateCondition checks whether a simple condition is satisfied by the context.
func evaluateCondition(cond *Condition, context map[string]interface{}) bool {
	if cond == nil {
		return true
	}

	fieldValue := resolveField(context, cond.Field)
	if fieldValue == nil {
		return false
	}

	op := cond.Operator
	condVal := cond.Value

	switch op {
	case "=":
		return fmt.Sprintf("%v", fieldValue) == condVal
	case "!=":
		return fmt.Sprintf("%v", fieldValue) != condVal
	case "<":
		fv, fvOk := toFloat(fieldValue)
		cv, cvOk := parseFloat(condVal)
		return fvOk && cvOk && fv < cv
	case ">":
		fv, fvOk := toFloat(fieldValue)
		cv, cvOk := parseFloat(condVal)
		return fvOk && cvOk && fv > cv
	case "<=":
		fv, fvOk := toFloat(fieldValue)
		cv, cvOk := parseFloat(condVal)
		return fvOk && cvOk && fv <= cv
	case ">=":
		fv, fvOk := toFloat(fieldValue)
		cv, cvOk := parseFloat(condVal)
		return fvOk && cvOk && fv >= cv
	default:
		return false
	}
}

func resolveField(context map[string]interface{}, field string) interface{} {
	parts := strings.Split(field, ".")
	var current interface{} = context

	for _, part := range parts {
		if current == nil {
			return nil
		}
		m, ok := current.(map[string]interface{})
		if !ok {
			return nil
		}
		current = m[part]
	}

	return current
}

func toFloat(v interface{}) (float64, bool) {
	switch n := v.(type) {
	case float64:
		return n, true
	case float32:
		return float64(n), true
	case int:
		return float64(n), true
	case int64:
		return float64(n), true
	case json.Number:
		f, err := n.Float64()
		return f, err == nil
	case string:
		return parseFloat(n)
	default:
		return 0, false
	}
}

func parseFloat(s string) (float64, bool) {
	f, err := strconv.ParseFloat(s, 64)
	return f, err == nil
}

// Evaluate evaluates a CCL document against an action/resource pair.
// It follows default-deny semantics: if no rule matches, the action is denied.
// When multiple rules match, specificity determines the winner, with deny
// winning over permit at equal specificity.
func Evaluate(doc *CCLDocument, action, resource string, context map[string]interface{}) *EvaluationResult {
	if context == nil {
		context = make(map[string]interface{})
	}

	var allMatches []Statement

	type matchedPD struct {
		stmt Statement
		spec int
	}
	var matchedPermitDeny []matchedPD

	// Check permits
	for _, stmt := range doc.Permits {
		if MatchAction(stmt.Action, action) && MatchResource(stmt.Resource, resource) {
			if evaluateCondition(stmt.Condition, context) {
				matchedPermitDeny = append(matchedPermitDeny, matchedPD{stmt: stmt, spec: specificity(stmt.Action, stmt.Resource)})
				allMatches = append(allMatches, stmt)
			}
		}
	}

	// Check denies
	for _, stmt := range doc.Denies {
		if MatchAction(stmt.Action, action) && MatchResource(stmt.Resource, resource) {
			if evaluateCondition(stmt.Condition, context) {
				matchedPermitDeny = append(matchedPermitDeny, matchedPD{stmt: stmt, spec: specificity(stmt.Action, stmt.Resource)})
				allMatches = append(allMatches, stmt)
			}
		}
	}

	// Check obligations (they contribute to allMatches but not to permit/deny decisions)
	for _, stmt := range doc.Obligations {
		if MatchAction(stmt.Action, action) && MatchResource(stmt.Resource, resource) {
			if evaluateCondition(stmt.Condition, context) {
				allMatches = append(allMatches, stmt)
			}
		}
	}

	// No matching permit/deny: default deny
	if len(matchedPermitDeny) == 0 {
		return &EvaluationResult{
			Permitted:  false,
			AllMatches: allMatches,
			Reason:     "No matching rules found; default deny",
		}
	}

	// Sort by specificity descending; at equal specificity, deny wins
	for i := 0; i < len(matchedPermitDeny); i++ {
		for j := i + 1; j < len(matchedPermitDeny); j++ {
			swap := false
			if matchedPermitDeny[j].spec > matchedPermitDeny[i].spec {
				swap = true
			} else if matchedPermitDeny[j].spec == matchedPermitDeny[i].spec {
				// deny wins at equal specificity
				if matchedPermitDeny[j].stmt.Type == StatementDeny && matchedPermitDeny[i].stmt.Type != StatementDeny {
					swap = true
				}
			}
			if swap {
				matchedPermitDeny[i], matchedPermitDeny[j] = matchedPermitDeny[j], matchedPermitDeny[i]
			}
		}
	}

	winner := matchedPermitDeny[0].stmt
	permitted := winner.Type == StatementPermit

	return &EvaluationResult{
		Permitted:   permitted,
		MatchedRule: &winner,
		AllMatches:  allMatches,
		Reason:      fmt.Sprintf("Matched %s rule for %s on %s", winner.Type, winner.Action, winner.Resource),
	}
}

// CheckRateLimit checks whether an action has exceeded its rate limit.
// currentCount is the number of times the action has been performed in the
// current window. windowStartMs and nowMs are epoch milliseconds.
func CheckRateLimit(doc *CCLDocument, metric string, currentCount int, windowStartMs, nowMs int64) *RateLimitResult {
	// Find the most specific matching limit
	var matched *Statement
	bestSpec := -1

	for i := range doc.Limits {
		limit := &doc.Limits[i]
		if MatchAction(limit.Action, metric) || MatchAction(limit.Metric, metric) {
			spec := specificity(limit.Action, "")
			if spec > bestSpec {
				bestSpec = spec
				matched = limit
			}
		}
	}

	if matched == nil {
		return &RateLimitResult{
			Exceeded:  false,
			Remaining: math.MaxInt32,
			Limit:     0,
		}
	}

	// Check if the time window has expired
	elapsed := nowMs - windowStartMs
	if float64(elapsed) > matched.Period {
		// Period expired; count resets
		return &RateLimitResult{
			Exceeded:  false,
			Remaining: int(matched.Limit),
			Limit:     int(matched.Limit),
		}
	}

	remaining := int(matched.Limit) - currentCount
	if remaining < 0 {
		remaining = 0
	}

	return &RateLimitResult{
		Exceeded:  currentCount >= int(matched.Limit),
		Remaining: remaining,
		Limit:     int(matched.Limit),
	}
}

// ----------------------------------------------------------------------------
// Narrowing validation
// ----------------------------------------------------------------------------

// patternsOverlap checks if two patterns can match any of the same strings.
func patternsOverlap(pattern1, pattern2 string) bool {
	if pattern1 == "**" || pattern2 == "**" {
		return true
	}
	if pattern1 == "*" || pattern2 == "*" {
		return true
	}
	if pattern1 == pattern2 {
		return true
	}

	// Check if pattern1 matches a concrete instance of pattern2 or vice versa
	concrete1 := strings.ReplaceAll(strings.ReplaceAll(pattern1, "**", "x"), "*", "x")
	concrete2 := strings.ReplaceAll(strings.ReplaceAll(pattern2, "**", "x"), "*", "x")

	if strings.Contains(pattern1, "/") || strings.Contains(pattern2, "/") {
		return MatchResource(pattern1, concrete2) || MatchResource(pattern2, concrete1)
	}
	return MatchAction(pattern1, concrete2) || MatchAction(pattern2, concrete1)
}

// isSubsetPattern checks if childPattern is a subset of parentPattern.
func isSubsetPattern(childPattern, parentPattern, separator string) bool {
	if parentPattern == "**" {
		return true
	}
	if childPattern == "**" && parentPattern != "**" {
		return false
	}

	childParts := filterEmpty(strings.Split(childPattern, separator))
	parentParts := filterEmpty(strings.Split(parentPattern, separator))

	return isSubsetSegments(childParts, 0, parentParts, 0)
}

func filterEmpty(parts []string) []string {
	var result []string
	for _, p := range parts {
		if p != "" {
			result = append(result, p)
		}
	}
	return result
}

func isSubsetSegments(child []string, ci int, parent []string, pi int) bool {
	if ci == len(child) && pi == len(parent) {
		return true
	}
	if pi == len(parent) {
		return false
	}
	if ci == len(child) {
		for i := pi; i < len(parent); i++ {
			if parent[i] != "**" {
				return false
			}
		}
		return true
	}

	pSeg := parent[pi]
	cSeg := child[ci]

	if pSeg == "**" {
		if isSubsetSegments(child, ci, parent, pi+1) {
			return true
		}
		return isSubsetSegments(child, ci+1, parent, pi)
	}

	if cSeg == "**" {
		if pSeg != "**" {
			return false
		}
		return isSubsetSegments(child, ci+1, parent, pi+1)
	}

	if pSeg == "*" {
		return isSubsetSegments(child, ci+1, parent, pi+1)
	}

	if cSeg == "*" {
		if pSeg != "*" && pSeg != "**" {
			return false
		}
		return isSubsetSegments(child, ci+1, parent, pi+1)
	}

	if cSeg != pSeg {
		return false
	}
	return isSubsetSegments(child, ci+1, parent, pi+1)
}

// ValidateNarrowing validates that a child CCL document only narrows
// the parent's constraints.
func ValidateNarrowing(parent, child *CCLDocument) *NarrowingResult {
	var violations []NarrowingViolation

	// Check each child permit against parent denies
	for i := range child.Permits {
		childPermit := &child.Permits[i]
		for j := range parent.Denies {
			parentDeny := &parent.Denies[j]
			if patternsOverlap(childPermit.Action, parentDeny.Action) &&
				patternsOverlap(childPermit.Resource, parentDeny.Resource) {
				violations = append(violations, NarrowingViolation{
					Message: fmt.Sprintf("Child permits '%s' on '%s' which parent denies", childPermit.Action, childPermit.Resource),
					Child:   childPermit,
					Parent:  parentDeny,
				})
			}
		}

		// Check if child permit is within a parent permit
		hasMatchingParentPermit := false
		for j := range parent.Permits {
			parentPermit := &parent.Permits[j]
			if isSubsetPattern(childPermit.Action, parentPermit.Action, ".") &&
				isSubsetPattern(childPermit.Resource, parentPermit.Resource, "/") {
				hasMatchingParentPermit = true
				break
			}
		}

		if len(parent.Permits) > 0 && !hasMatchingParentPermit {
			closestParent := &parent.Permits[0]
			violations = append(violations, NarrowingViolation{
				Message: fmt.Sprintf("Child permit '%s' on '%s' is not a subset of any parent permit", childPermit.Action, childPermit.Resource),
				Child:   childPermit,
				Parent:  closestParent,
			})
		}
	}

	return &NarrowingResult{
		Valid:      len(violations) == 0,
		Violations: violations,
	}
}

// Merge combines a parent and child CCL document with deny-wins semantics.
func Merge(parent, child *CCLDocument) *CCLDocument {
	var statements []Statement

	// All denies from both
	statements = append(statements, parent.Denies...)
	statements = append(statements, child.Denies...)

	// All permits from both
	statements = append(statements, child.Permits...)
	statements = append(statements, parent.Permits...)

	// All obligations from both
	statements = append(statements, parent.Obligations...)
	statements = append(statements, child.Obligations...)

	// Limits: take the more restrictive for the same action
	limitsByAction := make(map[string]Statement)
	for _, limit := range parent.Limits {
		existing, exists := limitsByAction[limit.Action]
		if !exists || limit.Limit < existing.Limit {
			limitsByAction[limit.Action] = limit
		}
	}
	for _, limit := range child.Limits {
		existing, exists := limitsByAction[limit.Action]
		if !exists || limit.Limit < existing.Limit {
			limitsByAction[limit.Action] = limit
		}
	}
	for _, limit := range limitsByAction {
		statements = append(statements, limit)
	}

	return buildCCLDocument(statements)
}

// Serialize converts a CCL document back to human-readable source text.
func Serialize(doc *CCLDocument) string {
	var lines []string
	for _, stmt := range doc.Statements {
		lines = append(lines, serializeStatement(stmt))
	}
	return strings.Join(lines, "\n")
}

func serializeStatement(stmt Statement) string {
	switch stmt.Type {
	case StatementPermit, StatementDeny:
		line := fmt.Sprintf("%s %s on '%s'", stmt.Type, stmt.Action, stmt.Resource)
		if stmt.Condition != nil {
			line += fmt.Sprintf(" when %s %s %s", stmt.Condition.Field, stmt.Condition.Operator, stmt.Condition.Value)
		}
		return line
	case StatementRequire:
		line := fmt.Sprintf("require %s on '%s'", stmt.Action, stmt.Resource)
		if stmt.Condition != nil {
			line += fmt.Sprintf(" when %s %s %s", stmt.Condition.Field, stmt.Condition.Operator, stmt.Condition.Value)
		}
		return line
	case StatementLimit:
		value, unit := bestTimeUnit(stmt.Period)
		return fmt.Sprintf("limit %s %.0f per %.0f %s", stmt.Action, stmt.Limit, value, unit)
	default:
		return ""
	}
}

func bestTimeUnit(periodMs float64) (float64, string) {
	const msPerDay = 86_400_000
	const msPerHour = 3_600_000
	const msPerMinute = 60_000
	const msPerSecond = 1000

	if periodMs >= msPerDay && math.Mod(periodMs, msPerDay) == 0 {
		return periodMs / msPerDay, "days"
	}
	if periodMs >= msPerHour && math.Mod(periodMs, msPerHour) == 0 {
		return periodMs / msPerHour, "hours"
	}
	if periodMs >= msPerMinute && math.Mod(periodMs, msPerMinute) == 0 {
		return periodMs / msPerMinute, "minutes"
	}
	return periodMs / msPerSecond, "seconds"
}
