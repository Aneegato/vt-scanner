package main

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/time/rate"
)

var (
	vtClient     *VTClient
	geminiClient *GeminiClient
	maxUploadB   int64 = 25 << 20

	dbReady bool // true if initDB succeeds
)

// --- simple per-IP rate limiter middleware ---
type ipLimiter struct {
	mu sync.Mutex
	m  map[string]*rate.Limiter
}

func newIPLimiter() *ipLimiter { return &ipLimiter{m: map[string]*rate.Limiter{}} }

func (l *ipLimiter) get(ip string) *rate.Limiter {
	l.mu.Lock()
	defer l.mu.Unlock()
	if lim, ok := l.m[ip]; ok {
		return lim
	}
	// ~1 request per 2s, burst 3
	lim := rate.NewLimiter(rate.Every(2*time.Second), 3)
	l.m[ip] = lim
	return lim
}

func main() {
	// === config/env ===
	if mb := os.Getenv("MAX_UPLOAD_MB"); mb != "" {
		if n, err := strconv.Atoi(mb); err == nil && n > 0 {
			maxUploadB = int64(n) << 20
		}
	}
	vtKey := os.Getenv("VT_API_KEY")
	if vtKey == "" {
		log.Fatal("VT_API_KEY is required (via env or /etc/vt-scanner.env)")
	}
	vtClient = NewVTClient(vtKey)

	if gk := os.Getenv("GEMINI_API_KEY"); gk != "" {
		var err error
		geminiClient, err = NewGeminiClient(gk)
		if err != nil {
			log.Fatalf("gemini client: %v", err)
		}
	}

	// === optional DB init (safe to skip if DATABASE_URL unset) ===
	if os.Getenv("DATABASE_URL") != "" {
		if err := initDB(context.Background()); err != nil {
			log.Printf("DB init failed (continuing without DB): %v", err)
		} else {
			dbReady = true
		}
	}

	// === server/bootstrap ===
	r := gin.Default()
	r.MaxMultipartMemory = maxUploadB
	r.SetTrustedProxies(nil)
	r.SetHTMLTemplate(loadTemplates())
	r.Static("/static/", "./web/static")

	// rate limit everything lightly
	lim := newIPLimiter()
	r.Use(func(c *gin.Context) {
		if !lim.get(c.ClientIP()).Allow() {
			c.AbortWithStatusJSON(429, gin.H{"error": "too many requests"})
			return
		}
		c.Next()
	})

	// HEAD & GET root -> upload form (+ recent from DB if available)
	r.HEAD("/", func(c *gin.Context) { c.Status(200) })
	r.GET("/", func(c *gin.Context) {
		data := gin.H{"Max": maxUploadB >> 20}
		if dbReady {
			if recent, err := getRecentScans(c.Request.Context(), 10); err == nil {
				data["Recent"] = recent
			}
		}
		c.HTML(200, "index.tmpl", data)
	})

	// Dedicated upload URL
	r.GET("/scan", func(c *gin.Context) {
		data := gin.H{"Max": maxUploadB >> 20}
		if dbReady {
			if recent, err := getRecentScans(c.Request.Context(), 10); err == nil {
				data["Recent"] = recent
			}
		}
		c.HTML(200, "index.tmpl", data)
	})

	// Pre-check by hash for client-side optimization (used by browser prehash step)
	r.GET("/api/lookup", func(c *gin.Context) {
		sha := strings.ToLower(strings.TrimSpace(c.Query("sha256")))
		if sha == "" {
			c.JSON(400, gin.H{"error": "missing sha256"})
			return
		}
		// Prefer DB if available; else ask VT (costs an API call)
		if dbReady {
			if s, err := getScanByHash(c.Request.Context(), sha); err == nil && s != nil {
				c.JSON(200, gin.H{"found": true, "url": "/result/sha256/" + sha})
				return
			}
		}
		if rep, st, _, _ := vtClient.GetFileByHash(c.Request.Context(), sha); st == 200 && rep != nil {
			c.JSON(200, gin.H{"found": true, "url": "/result/sha256/" + sha})
			return
		}
		c.JSON(200, gin.H{"found": false})
	})

	// Upload → smart scan (precheck hash, upload if needed, resilient polling)
	r.POST("/upload", func(c *gin.Context) {
		file, err := c.FormFile("file")
		if err != nil {
			renderErr(c, http.StatusBadRequest, "File required")
			return
		}
		if file.Size > maxUploadB {
			renderErr(c, http.StatusRequestEntityTooLarge, "File too large")
			return
		}

		// Save to temp, then scan
		tmp := filepath.Join(os.TempDir(), randomName()+"_"+filepath.Base(file.Filename))
		if err := c.SaveUploadedFile(file, tmp); err != nil {
			renderErr(c, http.StatusInternalServerError, "Save failed")
			return
		}
		defer os.Remove(tmp)

		ctx := c.Request.Context()
		a, id, sha, fromCache, err := vtClient.ScanFileSmart(ctx, tmp, 2*time.Minute)
		if err != nil {
			// Friendly “pending / try again soon” instead of hard fail
			renderErr(c, 200, "Analysis is still processing on VirusTotal. Please refresh in a few seconds.")
			return
		}

		// Optional: persist summary to DB (hash cache/history) if available
		if dbReady {
			norm := Summarize(a, id)
			// Build a minimal Scan row (assuming db.go Scan struct)
			_ = insertScan(ctx, &Scan{
				SHA256:         sha,
				FileName:       file.Filename,
				SizeBytes:      file.Size,
				MIME:           file.Header.Get("Content-Type"),
				VTAnalysisID:   id,
				VTVerdict:      norm.Verdict,
				DetectionRatio: parseRatio(norm.DetectionRatio),
				VTJSON:         mustJSON(a),
			})
		}

		// Redirect by hash if we didn’t get a stable analysis ID (or we used cache)
		if fromCache || id == "" || id == "(from-hash)" || id == "(conflict)" {
			c.Redirect(303, "/result/sha256/"+sha)
			return
		}
		c.Redirect(303, "/result/"+id)
	})

	// Result by analysis ID (existing flow)
	r.GET("/result/:id", func(c *gin.Context) {
		id := c.Param("id")
		anal, err := vtClient.GetAnalysis(c.Request.Context(), id)
		if err != nil {
			renderErr(c, 502, fmt.Sprintf("VirusTotal error: %v", err))
			return
		}
		sum := Summarize(anal, id)

		//  Pass a map with SHA256 present (empty if unknown)
		c.HTML(200, "result.tmpl", gin.H{
			"AnalysisID":     sum.AnalysisID,
			"Verdict":        sum.Verdict,
			"DetectionRatio": sum.DetectionRatio,
			"TopFindings":    sum.TopFindings,
			"SHA256":         "", // ensure template can reference .SHA256 safely
		})
	})

	// Result by SHA-256 (permalink; uses VT file report, no analysis id needed)
	r.GET("/result/sha256/:sha", func(c *gin.Context) {
		sha := strings.ToLower(strings.TrimSpace(c.Param("sha")))
		rep, st, _, err := vtClient.GetFileByHash(c.Request.Context(), sha)
		if err != nil || st != 200 || rep == nil {
			renderErr(c, 404, "Result not found yet. Try again in a few seconds.")
			return
		}
		a := fileReportToAnalysis(rep)
		sum := Summarize(a, "from-hash")
		var firstSeen, lastSeen string
		var scanCount int
		if dbReady {
			if s, err := getScanByHash(c.Request.Context(), sha); err == nil && s != nil {
				firstSeen = s.CreatedAt.Format("2006-01-02 15:04")
				lastSeen = s.LastSeen.Format("2006-01-02 15:04")
				scanCount = s.ScanCount
			}
		}
		c.HTML(200, "result.tmpl", gin.H{
			"AnalysisID":     sum.AnalysisID,
			"Verdict":        sum.Verdict,
			"DetectionRatio": sum.DetectionRatio,
			"TopFindings":    sum.TopFindings,
			"SHA256":         sha,       // remains hidden in meta
			"FirstSeen":      firstSeen, // NEW
			"LastSeen":       lastSeen,  // NEW
			"ScanCount":      scanCount, // NEW
		})

	})

	// History (DB only; renders on index.tmpl)
	r.GET("/history", func(c *gin.Context) {
		if !dbReady {
			c.HTML(200, "index.tmpl", gin.H{"Max": maxUploadB >> 20, "Recent": []any{}})
			return
		}
		recent, _ := getRecentScans(c.Request.Context(), 100)
		c.HTML(200, "index.tmpl", gin.H{"Max": maxUploadB >> 20, "Recent": recent})
	})

	// Explain: accept either analysis_id OR sha256
	r.POST("/explain", func(c *gin.Context) {
		if geminiClient == nil {
			c.JSON(200, gin.H{"explanation": "GenAI not configured."})
			return
		}
		var in struct {
			AnalysisID string `json:"analysis_id"`
			SHA256     string `json:"sha256"`
		}
		if err := c.ShouldBindJSON(&in); err != nil {
			c.JSON(400, gin.H{"error": "invalid JSON body"})
			return
		}

		var a *VTAnalysis
		var idForSummary string

		switch {
		case strings.TrimSpace(in.AnalysisID) != "" && len(in.AnalysisID) >= 9:
			anal, err := vtClient.GetAnalysis(c.Request.Context(), in.AnalysisID)
			if err != nil {
				c.JSON(502, gin.H{"error": fmt.Sprintf("VirusTotal error: %v", err)})
				return
			}
			a = anal
			idForSummary = in.AnalysisID

		case strings.TrimSpace(in.SHA256) != "":
			rep, st, _, err := vtClient.GetFileByHash(c.Request.Context(), strings.ToLower(in.SHA256))
			if err != nil || st != 200 || rep == nil {
				c.JSON(404, gin.H{"error": "hash not found yet"})
				return
			}
			a = fileReportToAnalysis(rep)
			idForSummary = "from-hash"

		default:
			c.JSON(400, gin.H{"error": "analysis_id or sha256 required"})
			return
		}

		sum := Summarize(a, idForSummary)
		b, _ := json.Marshal(sum)
		text, err := geminiClient.Explain(c.Request.Context(), string(b))
		if err != nil {
			c.JSON(502, gin.H{"error": fmt.Sprintf("Gemini error: %v", err)})
			return
		}

		// persist explanation if DB is available and sha provided
		if dbReady && in.SHA256 != "" {
			_ = saveExplanation(c.Request.Context(), strings.ToLower(in.SHA256), text)
		}

		c.JSON(200, gin.H{"explanation": text})
	})

	// Health / readiness / metrics
	r.GET("/health", func(c *gin.Context) { c.String(200, "ok") })
	r.GET("/ready", func(c *gin.Context) {
		if dbReady {
			if err := db.PingContext(c.Request.Context()); err != nil {
				c.String(500, "db down")
				return
			}
		}
		c.String(200, "ready")
	})
	r.GET("/metrics", func(c *gin.Context) {
		type M struct {
			ScansTotal int `json:"scans_total"`
		}
		m := M{}
		if dbReady {
			_ = db.QueryRowContext(c.Request.Context(), `SELECT COUNT(*) FROM scans`).Scan(&m.ScansTotal)
		}
		c.JSON(200, m)
	})

	r.GET("/api/result-json/*id", func(c *gin.Context) {
		id := strings.TrimPrefix(c.Param("id"), "/")
		if id == "" {
			c.Status(400)
			return
		}

		// treat 64-hex as sha256; otherwise assume analysis id
		hex64 := regexp.MustCompile(`^[0-9a-fA-F]{64}$`)
		if hex64.MatchString(id) {
			// SHA-256 path
			rep, st, body, err := vtClient.GetFileByHash(c.Request.Context(), strings.ToLower(id))
			if err != nil || st != 200 || rep == nil {
				c.Data(st, "application/json", body)
				return
			}
			if c.Query("download") == "1" {
				c.Header("Content-Disposition", fmt.Sprintf(`attachment; filename="%s.json"`, id))
			}
			c.JSON(200, rep)
			return
		}

		// analysis id path
		a, err := vtClient.GetAnalysis(c.Request.Context(), id)
		if err != nil {
			c.Status(404)
			return
		}
		if c.Query("download") == "1" {
			c.Header("Content-Disposition", fmt.Sprintf(`attachment; filename="%s.json"`, id))
		}
		c.JSON(200, a)
	})

	r.POST("/rescan", func(c *gin.Context) {
		sha := strings.ToLower(strings.TrimSpace(c.PostForm("sha256")))
		if sha == "" {
			c.Redirect(302, "/")
			return
		}
		if _, err := vtClient.ReanalyzeHash(c.Request.Context(), sha); err != nil {
			renderErr(c, 502, "VT re-scan failed: "+err.Error())
			return
		}
		c.Redirect(303, "/result/sha256/"+sha)
	})

	r.GET("/malicious", func(c *gin.Context) {
		if !dbReady {
			renderErr(c, 200, "DB not enabled")
			return
		}
		rows, err := db.QueryContext(c.Request.Context(), `
		SELECT sha256, filename, COALESCE(size_bytes,0), COALESCE(mime,''), created_at
		FROM scans
		WHERE vt_verdict='malicious'
		ORDER BY created_at DESC
		LIMIT 100`)
		if err != nil {
			renderErr(c, 500, err.Error())
			return
		}
		defer rows.Close()

		var out []Scan
		for rows.Next() {
			var s Scan
			if err := rows.Scan(&s.SHA256, &s.FileName, &s.SizeBytes, &s.MIME, &s.CreatedAt); err == nil {
				out = append(out, s)
			}
		}
		c.HTML(200, "index.tmpl", gin.H{"Max": maxUploadB >> 20, "Recent": out})
	})

	r.GET("/api/search", func(c *gin.Context) {
		if !dbReady {
			c.JSON(200, []any{})
			return
		}
		q := strings.TrimSpace(c.Query("q"))
		if q == "" {
			c.JSON(400, gin.H{"error": "missing q"})
			return
		}

		rows, err := db.QueryContext(c.Request.Context(), `
		SELECT sha256, filename, COALESCE(size_bytes,0), COALESCE(mime,''), vt_verdict, created_at
		FROM scans
		WHERE filename ILIKE '%' || $1 || '%'
		ORDER BY created_at DESC
		LIMIT 50`, q)
		if err != nil {
			c.JSON(500, gin.H{"error": err.Error()})
			return
		}
		defer rows.Close()

		type Row struct {
			SHA256 string    `json:"sha256"`
			File   string    `json:"file"`
			Size   int64     `json:"size"`
			MIME   string    `json:"mime"`
			Verd   string    `json:"verdict"`
			When   time.Time `json:"created_at"`
		}
		var out []Row
		for rows.Next() {
			var r Row
			_ = rows.Scan(&r.SHA256, &r.File, &r.Size, &r.MIME, &r.Verd, &r.When)
			out = append(out, r)
		}
		c.JSON(200, out)
	})

	r.GET("/export.csv", func(c *gin.Context) {
		if !dbReady {
			c.String(200, "")
			return
		}
		c.Header("Content-Type", "text/csv")
		c.Header("Content-Disposition", `attachment; filename="scans.csv"`)

		w := csv.NewWriter(c.Writer)
		_ = w.Write([]string{"sha256", "filename", "size_bytes", "mime", "verdict", "detection_ratio", "created_at", "last_seen", "scan_count"})

		rows, err := db.QueryContext(c.Request.Context(), `
		SELECT sha256, filename, COALESCE(size_bytes,0), COALESCE(mime,''), COALESCE(vt_verdict,''), 
		       COALESCE(detection_ratio,0), created_at, COALESCE(last_seen, created_at), COALESCE(scan_count,1)
		FROM scans
		ORDER BY created_at DESC
		LIMIT 1000`)
		if err != nil {
			return
		}
		defer rows.Close()

		for rows.Next() {
			var sha, fn, mime, verdict string
			var size int64
			var ratio float64
			var created, last time.Time
			var count int
			_ = rows.Scan(&sha, &fn, &size, &mime, &verdict, &ratio, &created, &last, &count)
			_ = w.Write([]string{
				sha, fn, fmt.Sprint(size), mime, verdict,
				fmt.Sprintf("%.3f", ratio), created.Format(time.RFC3339), last.Format(time.RFC3339), fmt.Sprint(count),
			})
		}
		w.Flush()
	})

	// listen
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	log.Printf("listening on :%s", port)
	_ = r.Run(":" + port)
}

func renderErr(c *gin.Context, code int, msg string) {
	c.HTML(code, "index.tmpl", gin.H{
		"Max": maxUploadB >> 20,
		"Err": msg,
	})
}

func loadTemplates() *template.Template {
	t := template.New("").Funcs(template.FuncMap{})
	t = template.Must(t.ParseFS(embedFS, "web/templates/*.tmpl"))
	return t
}

// helper: convert "x/y" into float64 ratio for DB
func parseRatio(s string) float64 {
	// very small helper; tolerate bad input
	var x, y float64
	if _, err := fmt.Sscanf(s, "%f/%f", &x, &y); err != nil || y == 0 {
		return 0
	}
	return x / y
}

func mustJSON(v any) []byte {
	b, _ := json.Marshal(v)
	return b
}
