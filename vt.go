package main

import (
	"bytes"
	"context"
	crand "crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	mrand "math/rand"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"time"
)

const vtBase = "https://www.virustotal.com/api/v3"

type VTClient struct {
	http   *http.Client
	apiKey string
}

func NewVTClient(apiKey string) *VTClient {
	// seed jitter for backoff
	mrand.Seed(time.Now().UnixNano())
	return &VTClient{
		http:   &http.Client{Timeout: 30 * time.Second},
		apiKey: apiKey,
	}
}

func randomName() string {
	var b [12]byte
	_, _ = crand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// ---------- Types ----------

type vtAnalysisCreate struct {
	Data struct {
		ID string `json:"id"`
	} `json:"data"`
}

type vtErrResp struct {
	Error struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

type VTAnalysis struct {
	Data struct {
		Attributes struct {
			Status string `json:"status"`
			Stats  struct {
				Harmless   int `json:"harmless"`
				Malicious  int `json:"malicious"`
				Suspicious int `json:"suspicious"`
				Undetected int `json:"undetected"`
				Timeout    int `json:"timeout"`
			} `json:"stats"`
			Results map[string]struct {
				Category  string `json:"category"`
				Result    string `json:"result"`
				Engine    string `json:"engine_name"`
				Method    string `json:"method"`
				EngineVer string `json:"engine_version"`
			} `json:"results"`
		} `json:"attributes"`
	} `json:"data"`
}

type VTFileReport struct {
	Data struct {
		Attributes struct {
			LastAnalysisStats struct {
				Harmless   int `json:"harmless"`
				Malicious  int `json:"malicious"`
				Suspicious int `json:"suspicious"`
				Undetected int `json:"undetected"`
				Timeout    int `json:"timeout"`
			} `json:"last_analysis_stats"`
			LastAnalysisResults map[string]struct {
				Category  string `json:"category"`
				Result    string `json:"result"`
				Engine    string `json:"engine_name"`
				Method    string `json:"method"`
				EngineVer string `json:"engine_version"`
			} `json:"last_analysis_results"`
		} `json:"attributes"`
	} `json:"data"`
}

// ---------- Helpers ----------

func parseVTError(b []byte) string {
	var e vtErrResp
	if json.Unmarshal(b, &e) == nil && e.Error.Code != "" {
		return fmt.Sprintf("%s: %s", e.Error.Code, e.Error.Message)
	}
	return string(b)
}

func (c *VTClient) vtGET(ctx context.Context, path string) (int, []byte, error) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, vtBase+path, nil)
	req.Header.Set("x-apikey", c.apiKey)
	req.Header.Set("User-Agent", "vt-scanner/1.0")
	resp, err := c.http.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, b, nil
}

func sha256OfFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func fileReportToAnalysis(rep *VTFileReport) *VTAnalysis {
	var a VTAnalysis
	a.Data.Attributes.Status = "completed"
	a.Data.Attributes.Stats.Harmless = rep.Data.Attributes.LastAnalysisStats.Harmless
	a.Data.Attributes.Stats.Malicious = rep.Data.Attributes.LastAnalysisStats.Malicious
	a.Data.Attributes.Stats.Suspicious = rep.Data.Attributes.LastAnalysisStats.Suspicious
	a.Data.Attributes.Stats.Undetected = rep.Data.Attributes.LastAnalysisStats.Undetected
	a.Data.Attributes.Stats.Timeout = rep.Data.Attributes.LastAnalysisStats.Timeout
	a.Data.Attributes.Results = rep.Data.Attributes.LastAnalysisResults
	return &a
}

// ---------- High-level smart scan ----------

// ScanFileSmart does:
// 1) compute SHA-256
// 2) if known hash → return latest file report (no upload)
// 3) else upload → poll analysis with ConflictError-aware backoff → fallback to file report
// Returns (*VTAnalysis, analysisID, sha256, fromCache, error)
func (c *VTClient) ScanFileSmart(ctx context.Context, path string, maxWait time.Duration) (*VTAnalysis, string, string, bool, error) {
	sha, err := sha256OfFile(path)
	if err != nil {
		return nil, "", "", false, err
	}

	// fast path: known hash
	if rep, st, _, _ := c.GetFileByHash(ctx, sha); st == 200 && rep != nil {
		return fileReportToAnalysis(rep), "(from-hash)", sha, true, nil
	}

	// unknown hash → upload once
	analysisID, err := c.UploadFile(ctx, path)
	if err != nil {
		// if VT returned a conflict (no id), poll by hash a bit
		if errors.Is(err, ErrVTConflict) {
			a, perr := c.PollAnalysisSmart(ctx, "", sha, maxWait)
			return a, "(conflict)", sha, false, perr
		}
		return nil, "", sha, false, err
	}

	// poll to completion (with conflict/backoff handling)
	a, err := c.PollAnalysisSmart(ctx, analysisID, sha, maxWait)
	return a, analysisID, sha, false, err
}

// ---------- Low-level VT calls ----------

var ErrVTConflict = errors.New("vt: conflict")

func (c *VTClient) UploadFile(ctx context.Context, path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	part, err := w.CreateFormFile("file", filepath.Base(path))
	if err != nil {
		return "", err
	}
	if _, err := io.Copy(part, f); err != nil {
		return "", err
	}
	_ = w.Close()

	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, vtBase+"/files", &buf)
	req.Header.Set("x-apikey", c.apiKey)
	req.Header.Set("Content-Type", w.FormDataContentType())

	res, err := c.http.Do(req)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()

	if res.StatusCode >= 300 {
		bb, _ := io.ReadAll(res.Body)
		// Handle ConflictError (transient)
		if res.StatusCode == 409 && bytes.Contains(bb, []byte(`"code":"ConflictError"`)) {
			// try to extract an ID-ish token; if found we could return it
			re := regexp.MustCompile(`[0-9a-f]{32,}`)
			if m := re.Find(bb); m != nil {
				return string(m), nil // let the poller handle it
			}
			return "", ErrVTConflict
		}
		return "", errors.New(parseVTError(bb))
	}

	var out vtAnalysisCreate
	if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
		return "", err
	}
	return out.Data.ID, nil
}

func (c *VTClient) GetAnalysis(ctx context.Context, id string) (*VTAnalysis, error) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, vtBase+"/analyses/"+id, nil)
	req.Header.Set("x-apikey", c.apiKey)
	res, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode >= 300 {
		bb, _ := io.ReadAll(res.Body)
		return nil, errors.New(parseVTError(bb))
	}
	var out VTAnalysis
	if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *VTClient) ReanalyzeHash(ctx context.Context, sha string) (string, error) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, vtBase+"/files/"+sha+"/analyse", nil)
	req.Header.Set("x-apikey", c.apiKey)
	res, err := c.http.Do(req)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()
	if res.StatusCode >= 300 {
		bb, _ := io.ReadAll(res.Body)
		return "", errors.New(parseVTError(bb))
	}
	var out vtAnalysisCreate
	if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
		return "", err
	}
	return out.Data.ID, nil
}

func (c *VTClient) GetFileByHash(ctx context.Context, sha string) (*VTFileReport, int, []byte, error) {
	st, body, err := c.vtGET(ctx, "/files/"+sha)
	if err != nil {
		return nil, st, body, err
	}
	if st != 200 {
		return nil, st, body, fmt.Errorf("vt files/%s: %s", sha, parseVTError(body))
	}
	var rep VTFileReport
	if err := json.Unmarshal(body, &rep); err != nil {
		return nil, st, body, err
	}
	return &rep, st, body, nil
}

// PollAnalysisSmart handles queued/in-progress, ConflictError (409), 202/404/503, 429 with backoff,
// and finally falls back to file report by hash.
func (c *VTClient) PollAnalysisSmart(ctx context.Context, analysisID, sha string, maxWait time.Duration) (*VTAnalysis, error) {
	deadline := time.Now().Add(maxWait)
	backoff := 1500 * time.Millisecond
	conflictRe := regexp.MustCompile(`[0-9a-f]{32,}`)

	// If we don't have an analysisID (e.g., Conflict on upload), poll by hash
	if analysisID == "" && sha != "" {
		for time.Now().Before(deadline) {
			if rep, st, _, _ := c.GetFileByHash(ctx, sha); st == 200 && rep != nil {
				return fileReportToAnalysis(rep), nil
			}
			time.Sleep(2 * time.Second)
		}
		return nil, fmt.Errorf("analysis pending; retry later")
	}

	for time.Now().Before(deadline) {
		st, body, err := c.vtGET(ctx, "/analyses/"+analysisID)
		if err == nil && st == 200 {
			var a VTAnalysis
			if json.Unmarshal(body, &a) == nil && a.Data.Attributes.Status == "completed" {
				return &a, nil
			}
			// queued / in-progress
			time.Sleep(2 * time.Second)
			continue
		}

		// 409 ConflictError → jittered exponential backoff
		if st == 409 && bytes.Contains(body, []byte(`"code":"ConflictError"`)) {
			if m := conflictRe.Find(body); m != nil {
				analysisID = string(m)
			}
			jitter := time.Duration(mrand.Intn(400)) * time.Millisecond
			time.Sleep(backoff + jitter)
			if backoff < 10*time.Second {
				backoff *= 2
			}
			continue
		}

		// transient statuses
		if st == 202 || st == 404 || st == 503 {
			time.Sleep(2 * time.Second)
			continue
		}

		if st == 429 {
			time.Sleep(10 * time.Second)
			continue
		}

		// unknown issue → break to fallback
		break
	}

	// Fallback to file report
	if sha != "" {
		if rep, st, body, err := c.GetFileByHash(ctx, sha); err == nil && st == 200 {
			return fileReportToAnalysis(rep), nil
		} else {
			return nil, fmt.Errorf("analysis pending; also failed to get file report: %s", parseVTError(body))
		}
	}

	return nil, fmt.Errorf("analysis still pending; please retry")
}

// ---------- Legacy summarize (unchanged) ----------

type Normalized struct {
	AnalysisID     string   `json:"analysis_id"`
	Verdict        string   `json:"verdict"`
	DetectionRatio string   `json:"detection_ratio"`
	TopFindings    []string `json:"top_findings"`
}

func Summarize(a *VTAnalysis, id string) Normalized {
	st := a.Data.Attributes.Stats
	total := st.Harmless + st.Malicious + st.Suspicious + st.Undetected + st.Timeout
	if total == 0 {
		total = 1
	}
	verdict := "clean"
	switch {
	case st.Malicious > 0:
		verdict = "malicious"
	case st.Suspicious > 0:
		verdict = "suspicious"
	case st.Harmless > 0:
		verdict = "clean" // explicitly clean by at least one engine
	default:
		verdict = "undetected" // nobody flagged it and nobody marked it clean
	}
	top := make([]string, 0, 5)
	for eng, r := range a.Data.Attributes.Results {
		if r.Category == "malicious" || r.Category == "suspicious" {
			top = append(top, fmt.Sprintf("%s: %s", eng, r.Result))
			if len(top) == 5 {
				break
			}
		}
	}
	return Normalized{
		AnalysisID:     id,
		Verdict:        verdict,
		DetectionRatio: fmt.Sprintf("%d/%d", st.Malicious+st.Suspicious, total),
		TopFindings:    top,
	}
}
