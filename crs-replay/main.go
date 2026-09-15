package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime/debug"
	"sort"
	"strings"

	"github.com/corazawaf/coraza-coreruleset/v4"
	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/types"
)

const (
	engineName = "coraza"
	corazaPath = "github.com/corazawaf/coraza/v3"
	crsPath    = "github.com/corazawaf/coraza-coreruleset/v4"
)

type eventFields struct {
	IP             string            `json:"ip"`
	Method         string            `json:"method"`
	Path           string            `json:"path"`
	Protocol       string            `json:"protocol"`
	Status         int               `json:"status"`
	Host           string            `json:"host"`
	Referer        string            `json:"referer"`
	UserAgent      string            `json:"user_agent"`
	ForwardedFor   string            `json:"forwarded_for"`
	ContentType    string            `json:"content_type"`
	Cookie         string            `json:"cookie"`
	RequestBody    *string           `json:"request_body"`
	ResponseBody   *string           `json:"response_body"`
	RequestHeaders map[string]string `json:"request_headers"`
}

type event struct {
	EventID    string `json:"event_id"`
	Timestamp  string `json:"timestamp"`
	SourceType string `json:"source_type"`
	eventFields
	Details eventFields `json:"details"`
}

type matchedVariable struct {
	Variable string `json:"variable"`
	Key      string `json:"key,omitempty"`
	Value    string `json:"value,omitempty"`
	Data     string `json:"data,omitempty"`
}

type matchedRule struct {
	ID               int               `json:"id"`
	Message          string            `json:"message"`
	Data             string            `json:"data,omitempty"`
	Phase            int               `json:"phase"`
	Severity         string            `json:"severity"`
	File             string            `json:"file,omitempty"`
	Line             int               `json:"line,omitempty"`
	Version          string            `json:"version,omitempty"`
	Tags             []string          `json:"tags"`
	IsAttack         bool              `json:"is_attack"`
	MatchedVariables []matchedVariable `json:"matched_variables"`
}

type coverage struct {
	Level           string   `json:"level"`
	Profile         string   `json:"profile"`
	ObservedFields  []string `json:"observed_fields"`
	MissingFields   []string `json:"missing_fields"`
	EvaluatedPhases []int    `json:"evaluated_phases"`
}

type replayResult struct {
	EventID     string        `json:"event_id,omitempty"`
	Timestamp   string        `json:"timestamp,omitempty"`
	Engine      string        `json:"engine"`
	EngineVer   string        `json:"engine_version"`
	CRSVer      string        `json:"crs_version"`
	Coverage    coverage      `json:"coverage"`
	Matched     []matchedRule `json:"matched_rules"`
	AttackCount int           `json:"attack_rule_count"`
	Error       string        `json:"error,omitempty"`
}

type requestData struct {
	clientIP      string
	method        string
	target        string
	protocol      string
	host          string
	status        int
	requestBody   *string
	responseBody  *string
	requestHeader map[string]string
}

type replayEngine struct {
	waf           coraza.WAF
	engineVersion string
	crsVersion    string
}

func newReplayEngine() (*replayEngine, error) {
	directives := `
Include @coraza.conf-recommended
Include @crs-setup.conf.example
Include @owasp_crs/*.conf
SecRuleRemoveById 920000-920999
`
	waf, err := coraza.NewWAF(
		coraza.NewWAFConfig().
			WithRootFS(coreruleset.FS).
			WithDirectives(directives).
			WithErrorCallback(func(types.MatchedRule) {}),
	)
	if err != nil {
		return nil, fmt.Errorf("load Coraza and CRS: %w", err)
	}
	return &replayEngine{
		waf:           waf,
		engineVersion: dependencyVersion(corazaPath),
		crsVersion:    dependencyVersion(crsPath),
	}, nil
}

func dependencyVersion(path string) string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "unknown"
	}
	for _, dependency := range info.Deps {
		if dependency.Path == path {
			return strings.TrimPrefix(dependency.Version, "v")
		}
	}
	return "unknown"
}

func first(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func firstInt(values ...int) int {
	for _, value := range values {
		if value != 0 {
			return value
		}
	}
	return 0
}

func firstBody(values ...*string) *string {
	for _, value := range values {
		if value != nil {
			return value
		}
	}
	return nil
}

func normalizeEvent(input event) requestData {
	headers := make(map[string]string)
	for key, value := range input.RequestHeaders {
		headers[key] = value
	}
	for key, value := range input.Details.RequestHeaders {
		headers[key] = value
	}

	knownHeaders := map[string]string{
		"Host":            first(input.Host, input.Details.Host),
		"User-Agent":      first(input.UserAgent, input.Details.UserAgent),
		"Referer":         first(input.Referer, input.Details.Referer),
		"X-Forwarded-For": first(input.ForwardedFor, input.Details.ForwardedFor),
		"Content-Type":    first(input.ContentType, input.Details.ContentType),
		"Cookie":          first(input.Cookie, input.Details.Cookie),
	}
	for key, value := range knownHeaders {
		if value != "" && value != "-" {
			headers[key] = value
		}
	}

	return requestData{
		clientIP:      first(input.IP, input.Details.IP),
		method:        first(input.Method, input.Details.Method, "GET"),
		target:        first(input.Path, input.Details.Path, "/"),
		protocol:      first(input.Protocol, input.Details.Protocol, "HTTP/1.1"),
		host:          first(input.Host, input.Details.Host),
		status:        firstInt(input.Status, input.Details.Status),
		requestBody:   firstBody(input.RequestBody, input.Details.RequestBody),
		responseBody:  firstBody(input.ResponseBody, input.Details.ResponseBody),
		requestHeader: headers,
	}
}

func hasAttackTag(tags []string) bool {
	for _, tag := range tags {
		if strings.HasPrefix(strings.ToLower(tag), "attack-") {
			return true
		}
	}
	return false
}

func convertMatchedRule(match types.MatchedRule) matchedRule {
	metadata := match.Rule()
	variables := make([]matchedVariable, 0, len(match.MatchedDatas()))
	for _, data := range match.MatchedDatas() {
		variables = append(variables, matchedVariable{
			Variable: data.Variable().Name(),
			Key:      data.Key(),
			Value:    data.Value(),
			Data:     data.Data(),
		})
	}
	return matchedRule{
		ID:               metadata.ID(),
		Message:          match.Message(),
		Data:             match.Data(),
		Phase:            int(metadata.Phase()),
		Severity:         metadata.Severity().String(),
		File:             metadata.File(),
		Line:             metadata.Line(),
		Version:          metadata.Version(),
		Tags:             metadata.Tags(),
		IsAttack:         hasAttackTag(metadata.Tags()),
		MatchedVariables: variables,
	}
}

func coverageFor(request requestData) coverage {
	observed := []string{"method", "path", "protocol"}
	missing := []string{}

	if request.clientIP != "" {
		observed = append(observed, "client_ip")
	} else {
		missing = append(missing, "client_ip")
	}
	for _, key := range []string{"Host", "User-Agent", "Referer", "X-Forwarded-For", "Content-Type", "Cookie"} {
		if _, ok := request.requestHeader[key]; ok {
			observed = append(observed, "request_header."+strings.ToLower(key))
		} else {
			missing = append(missing, "request_header."+strings.ToLower(key))
		}
	}
	if request.requestBody != nil {
		observed = append(observed, "request_body")
	} else {
		missing = append(missing, "request_body")
	}
	if request.status != 0 {
		observed = append(observed, "response_status")
	} else {
		missing = append(missing, "response_status")
	}
	if request.responseBody != nil {
		observed = append(observed, "response_body")
	} else {
		missing = append(missing, "response_body")
	}
	sort.Strings(observed)
	sort.Strings(missing)

	level := "full"
	if len(missing) > 0 {
		level = "partial"
	}
	return coverage{
		Level:           level,
		Profile:         "sparse-access-log",
		ObservedFields:  observed,
		MissingFields:   missing,
		EvaluatedPhases: []int{1, 2},
	}
}

func (engine *replayEngine) replay(input event) replayResult {
	request := normalizeEvent(input)
	result := replayResult{
		EventID:   input.EventID,
		Timestamp: input.Timestamp,
		Engine:    engineName,
		EngineVer: engine.engineVersion,
		CRSVer:    engine.crsVersion,
		Coverage:  coverageFor(request),
		Matched:   []matchedRule{},
	}

	tx := engine.waf.NewTransaction()
	defer func() {
		_ = tx.Close()
	}()
	clientIP := request.clientIP
	if clientIP == "" {
		clientIP = "0.0.0.0"
	}
	tx.ProcessConnection(clientIP, 0, "0.0.0.0", 0)
	tx.ProcessURI(request.target, request.method, request.protocol)
	if request.host != "" {
		tx.SetServerName(request.host)
	}
	for key, value := range request.requestHeader {
		tx.AddRequestHeader(key, value)
	}
	tx.ProcessRequestHeaders()

	if request.requestBody != nil {
		if _, _, err := tx.WriteRequestBody([]byte(*request.requestBody)); err != nil {
			result.Error = fmt.Sprintf("write request body: %v", err)
			return result
		}
	}
	if _, err := tx.ProcessRequestBody(); err != nil {
		result.Error = fmt.Sprintf("process request body: %v", err)
		return result
	}

	for _, match := range tx.MatchedRules() {
		converted := convertMatchedRule(match)
		result.Matched = append(result.Matched, converted)
		if converted.IsAttack {
			result.AttackCount++
		}
	}
	tx.ProcessLogging()
	return result
}

func run(input io.Reader, output io.Writer) error {
	engine, err := newReplayEngine()
	if err != nil {
		return err
	}

	scanner := bufio.NewScanner(input)
	buffer := make([]byte, 64*1024)
	scanner.Buffer(buffer, 16*1024*1024)
	encoder := json.NewEncoder(output)
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var inputEvent event
		if err := json.Unmarshal([]byte(line), &inputEvent); err != nil {
			result := replayResult{
				Engine:    engineName,
				EngineVer: engine.engineVersion,
				CRSVer:    engine.crsVersion,
				Matched:   []matchedRule{},
				Error:     fmt.Sprintf("decode line %d: %v", lineNumber, err),
			}
			if encodeErr := encoder.Encode(result); encodeErr != nil {
				return encodeErr
			}
			continue
		}
		if err := encoder.Encode(engine.replay(inputEvent)); err != nil {
			return err
		}
	}
	return scanner.Err()
}

func main() {
	if err := run(os.Stdin, os.Stdout); err != nil && !errors.Is(err, io.EOF) {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
