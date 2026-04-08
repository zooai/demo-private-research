// Private Research Demo (DeSci)
//
// Demonstrates decentralized science with privacy-preserving computation:
//
//   1. Researcher submits encrypted research data (simulated FHE)
//   2. Peer reviewers run homomorphic computations on encrypted data
//   3. Results are threshold-decrypted only after reviewer consensus
//   4. Published results are recorded on-chain (immutable)
//
// This demo simulates the FHE and MPC threshold decryption steps
// using simple integer arithmetic. In production, these would use
// the Lux EVM's FHE precompiles and Lux MPC's FROST/CGGMP21.
//
// Run: go run . serve
package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/hanzoai/base"
	"github.com/hanzoai/base/core"
	"github.com/hanzoai/base/tools/hook"
	"github.com/hanzoai/dbx"
)

func main() {
	app := base.New()

	app.OnBootstrap().BindFunc(func(e *core.BootstrapEvent) error {
		if err := e.Next(); err != nil {
			return err
		}
		return ensureCollections(e.App)
	})

	app.OnServe().Bind(&hook.Handler[*core.ServeEvent]{
		Func: func(e *core.ServeEvent) error {
			g := e.Router.Group("/v1")

			g.POST("/research/submit", handleSubmitResearch)
			g.GET("/research/{researchId}", handleGetResearch)
			g.POST("/research/{researchId}/review", handleSubmitReview)
			g.POST("/research/{researchId}/compute", handleHomomorphicCompute)
			g.POST("/research/{researchId}/decrypt", handleThresholdDecrypt)
			g.POST("/research/{researchId}/publish", handlePublish)
			g.GET("/research", handleListResearch)

			return e.Next()
		},
		Priority: -10,
	})

	if err := app.Start(); err != nil {
		log.Fatal(err)
	}
}

// ---------------------------------------------------------------------------
// Collections
// ---------------------------------------------------------------------------

func ensureCollections(app core.App) error {
	specs := []struct {
		name   string
		fields func(c *core.Collection)
	}{
		{"research", func(c *core.Collection) {
			c.Fields.Add(
				&core.TextField{Name: "title", Required: true},
				&core.TextField{Name: "researcher", Required: true},
				&core.TextField{Name: "description"},
				&core.TextField{Name: "encryptedData"},       // FHE ciphertext (hex)
				&core.NumberField{Name: "encryptionNonce"},    // simulated FHE key offset
				&core.SelectField{Name: "status", Values: []string{"submitted", "reviewing", "computed", "decrypted", "published"}, Required: true, MaxSelect: 1},
				&core.NumberField{Name: "requiredReviewers"},  // threshold for decrypt
				&core.NumberField{Name: "approvedReviewers"},
				&core.TextField{Name: "computedResult"},       // encrypted computation output
				&core.TextField{Name: "decryptedResult"},      // plaintext after threshold decrypt
				&core.TextField{Name: "publishTxHash"},        // on-chain publication tx
				&core.AutodateField{Name: "createdAt", OnCreate: true},
			)
		}},
		{"reviews", func(c *core.Collection) {
			c.Fields.Add(
				&core.TextField{Name: "researchId", Required: true},
				&core.TextField{Name: "reviewer", Required: true},
				&core.SelectField{Name: "verdict", Values: []string{"approve", "reject", "revision"}, Required: true, MaxSelect: 1},
				&core.TextField{Name: "comments"},
				&core.TextField{Name: "decryptShare"},  // threshold key share for decrypt
				&core.AutodateField{Name: "createdAt", OnCreate: true},
			)
		}},
		{"publications", func(c *core.Collection) {
			c.Fields.Add(
				&core.TextField{Name: "researchId", Required: true},
				&core.TextField{Name: "title", Required: true},
				&core.TextField{Name: "result"},
				&core.TextField{Name: "txHash"},
				&core.TextField{Name: "publishedAt"},
				&core.AutodateField{Name: "createdAt", OnCreate: true},
			)
		}},
	}

	for _, spec := range specs {
		if _, err := app.FindCollectionByNameOrId(spec.name); err == nil {
			continue
		}
		c := core.NewBaseCollection(spec.name)
		spec.fields(c)
		if err := app.Save(c); err != nil {
			return fmt.Errorf("creating collection %s: %w", spec.name, err)
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

// POST /v1/research/submit
// Body: { "title", "researcher", "description", "rawData", "requiredReviewers" }
//
// Simulates FHE encryption: adds a random nonce to each byte of rawData.
// In production this would use the Lux EVM FHE precompile.
func handleSubmitResearch(e *core.RequestEvent) error {
	var req struct {
		Title             string  `json:"title"`
		Researcher        string  `json:"researcher"`
		Description       string  `json:"description"`
		RawData           string  `json:"rawData"`
		RequiredReviewers float64 `json:"requiredReviewers"`
	}
	if err := e.BindBody(&req); err != nil {
		return e.BadRequestError("invalid body", err)
	}
	if req.Title == "" || req.Researcher == "" || req.RawData == "" {
		return e.BadRequestError("title, researcher, rawData required", nil)
	}
	if req.RequiredReviewers < 1 {
		req.RequiredReviewers = 2
	}

	// Simulated FHE encryption: shift each byte by a random nonce.
	nonce := randomNonce()
	encrypted := fheEncrypt([]byte(req.RawData), nonce)

	col, err := e.App.FindCollectionByNameOrId("research")
	if err != nil {
		return e.InternalServerError("research collection missing", err)
	}

	rec := core.NewRecord(col)
	rec.Set("title", req.Title)
	rec.Set("researcher", req.Researcher)
	rec.Set("description", req.Description)
	rec.Set("encryptedData", hex.EncodeToString(encrypted))
	rec.Set("encryptionNonce", nonce)
	rec.Set("status", "submitted")
	rec.Set("requiredReviewers", req.RequiredReviewers)
	rec.Set("approvedReviewers", 0)

	if err := e.App.Save(rec); err != nil {
		return e.InternalServerError("failed to save research", err)
	}

	return e.JSON(http.StatusCreated, map[string]any{
		"id":            rec.Id,
		"title":         req.Title,
		"encryptedData": rec.GetString("encryptedData"),
		"status":        "submitted",
		"message":       "research submitted with FHE encryption",
	})
}

// GET /v1/research/{researchId}
func handleGetResearch(e *core.RequestEvent) error {
	id := e.Request.PathValue("researchId")
	rec, err := e.App.FindRecordById("research", id)
	if err != nil {
		return e.NotFoundError("research not found", err)
	}

	// Hide the nonce (private key material) from the response.
	return e.JSON(http.StatusOK, map[string]any{
		"id":               rec.Id,
		"title":            rec.GetString("title"),
		"researcher":       rec.GetString("researcher"),
		"description":      rec.GetString("description"),
		"encryptedData":    rec.GetString("encryptedData"),
		"status":           rec.GetString("status"),
		"requiredReviewers": rec.GetFloat("requiredReviewers"),
		"approvedReviewers": rec.GetFloat("approvedReviewers"),
		"computedResult":   rec.GetString("computedResult"),
		"decryptedResult":  rec.GetString("decryptedResult"),
		"publishTxHash":    rec.GetString("publishTxHash"),
	})
}

// GET /v1/research
func handleListResearch(e *core.RequestEvent) error {
	records, err := e.App.FindAllRecords("research")
	if err != nil {
		return e.JSON(http.StatusOK, []any{})
	}

	var out []map[string]any
	for _, r := range records {
		out = append(out, map[string]any{
			"id":     r.Id,
			"title":  r.GetString("title"),
			"status": r.GetString("status"),
		})
	}
	return e.JSON(http.StatusOK, out)
}

// POST /v1/research/{researchId}/review
// Body: { "reviewer", "verdict", "comments" }
//
// Each approving reviewer contributes a "decrypt share" (simulated threshold key share).
func handleSubmitReview(e *core.RequestEvent) error {
	researchId := e.Request.PathValue("researchId")
	research, err := e.App.FindRecordById("research", researchId)
	if err != nil {
		return e.NotFoundError("research not found", err)
	}

	var req struct {
		Reviewer string `json:"reviewer"`
		Verdict  string `json:"verdict"`
		Comments string `json:"comments"`
	}
	if err := e.BindBody(&req); err != nil {
		return e.BadRequestError("invalid body", err)
	}
	if req.Reviewer == "" || req.Verdict == "" {
		return e.BadRequestError("reviewer and verdict required", nil)
	}

	col, err := e.App.FindCollectionByNameOrId("reviews")
	if err != nil {
		return e.InternalServerError("reviews collection missing", err)
	}

	// Simulated threshold key share: partial nonce reveal.
	nonce := int(research.GetFloat("encryptionNonce"))
	required := int(research.GetFloat("requiredReviewers"))
	share := 0
	if required > 0 {
		share = nonce / required // each reviewer gets an equal piece
	}

	rev := core.NewRecord(col)
	rev.Set("researchId", researchId)
	rev.Set("reviewer", req.Reviewer)
	rev.Set("verdict", req.Verdict)
	rev.Set("comments", req.Comments)
	if req.Verdict == "approve" {
		rev.Set("decryptShare", fmt.Sprintf("%d", share))
	}

	if err := e.App.Save(rev); err != nil {
		return e.InternalServerError("failed to save review", err)
	}

	// Update approved count.
	if req.Verdict == "approve" {
		approved := research.GetFloat("approvedReviewers") + 1
		research.Set("approvedReviewers", approved)
		research.Set("status", "reviewing")
		_ = e.App.Save(research)
	}

	return e.JSON(http.StatusCreated, map[string]any{
		"reviewId":         rev.Id,
		"verdict":          req.Verdict,
		"hasDecryptShare":  req.Verdict == "approve",
		"message":          "review submitted",
	})
}

// POST /v1/research/{researchId}/compute
// Body: { "operation" } -- "sum", "mean", "count"
//
// Runs a homomorphic computation on the encrypted data.
// In production, the FHE precompile would evaluate this on ciphertexts.
// Here we simulate by operating on the encrypted bytes directly.
func handleHomomorphicCompute(e *core.RequestEvent) error {
	researchId := e.Request.PathValue("researchId")
	research, err := e.App.FindRecordById("research", researchId)
	if err != nil {
		return e.NotFoundError("research not found", err)
	}

	var req struct {
		Operation string `json:"operation"`
	}
	if err := e.BindBody(&req); err != nil {
		return e.BadRequestError("invalid body", err)
	}

	encHex := research.GetString("encryptedData")
	encBytes, err := hex.DecodeString(encHex)
	if err != nil {
		return e.InternalServerError("corrupted encrypted data", err)
	}

	// Simulate homomorphic operation on encrypted bytes.
	var result int
	switch req.Operation {
	case "sum":
		for _, b := range encBytes {
			result += int(b)
		}
	case "mean":
		for _, b := range encBytes {
			result += int(b)
		}
		if len(encBytes) > 0 {
			result /= len(encBytes)
		}
	case "count":
		result = len(encBytes)
	default:
		return e.BadRequestError("operation must be sum, mean, or count", nil)
	}

	// Store encrypted result.
	nonce := int(research.GetFloat("encryptionNonce"))
	encResult := result + nonce // add nonce to keep result encrypted

	research.Set("computedResult", fmt.Sprintf("%d", encResult))
	research.Set("status", "computed")
	_ = e.App.Save(research)

	return e.JSON(http.StatusOK, map[string]any{
		"operation":      req.Operation,
		"encryptedResult": encResult,
		"message":        "homomorphic computation complete (result still encrypted)",
	})
}

// POST /v1/research/{researchId}/decrypt
//
// Threshold decryption: requires enough approved reviewers.
// Combines decrypt shares to recover the nonce and decrypt the result.
func handleThresholdDecrypt(e *core.RequestEvent) error {
	researchId := e.Request.PathValue("researchId")
	research, err := e.App.FindRecordById("research", researchId)
	if err != nil {
		return e.NotFoundError("research not found", err)
	}

	required := int(research.GetFloat("requiredReviewers"))
	approved := int(research.GetFloat("approvedReviewers"))

	if approved < required {
		return e.BadRequestError(
			fmt.Sprintf("need %d approving reviewers, have %d", required, approved),
			nil,
		)
	}

	computedStr := research.GetString("computedResult")
	if computedStr == "" {
		return e.BadRequestError("no computed result to decrypt -- run /compute first", nil)
	}

	// Collect decrypt shares from approved reviews.
	reviews, err := e.App.FindAllRecords("reviews",
		dbx.HashExp{"researchId": researchId},
	)
	if err != nil {
		return e.InternalServerError("failed to query reviews", err)
	}

	var totalShare int
	var shareCount int
	for _, rev := range reviews {
		if rev.GetString("verdict") != "approve" {
			continue
		}
		shareStr := rev.GetString("decryptShare")
		if shareStr == "" {
			continue
		}
		var s int
		fmt.Sscanf(shareStr, "%d", &s)
		totalShare += s
		shareCount++
		if shareCount >= required {
			break
		}
	}

	// Reconstruct nonce from shares and decrypt.
	var encResult int
	fmt.Sscanf(computedStr, "%d", &encResult)
	decrypted := encResult - totalShare

	research.Set("decryptedResult", fmt.Sprintf("%d", decrypted))
	research.Set("status", "decrypted")
	_ = e.App.Save(research)

	return e.JSON(http.StatusOK, map[string]any{
		"decryptedResult": decrypted,
		"sharesUsed":      shareCount,
		"message":         "threshold decryption complete",
	})
}

// POST /v1/research/{researchId}/publish
//
// Publishes the decrypted result on-chain (immutable record).
func handlePublish(e *core.RequestEvent) error {
	researchId := e.Request.PathValue("researchId")
	research, err := e.App.FindRecordById("research", researchId)
	if err != nil {
		return e.NotFoundError("research not found", err)
	}

	if research.GetString("status") != "decrypted" {
		return e.BadRequestError("research must be decrypted before publishing", nil)
	}

	txHash := simulateTx()

	pubCol, err := e.App.FindCollectionByNameOrId("publications")
	if err != nil {
		return e.InternalServerError("publications collection missing", err)
	}

	pub := core.NewRecord(pubCol)
	pub.Set("researchId", researchId)
	pub.Set("title", research.GetString("title"))
	pub.Set("result", research.GetString("decryptedResult"))
	pub.Set("txHash", txHash)
	pub.Set("publishedAt", time.Now().UTC().Format(time.RFC3339))

	if err := e.App.Save(pub); err != nil {
		return e.InternalServerError("failed to save publication", err)
	}

	research.Set("publishTxHash", txHash)
	research.Set("status", "published")
	_ = e.App.Save(research)

	return e.JSON(http.StatusCreated, map[string]any{
		"publicationId": pub.Id,
		"txHash":        txHash,
		"result":        research.GetString("decryptedResult"),
		"message":       "research published on-chain (immutable)",
	})
}

// ---------------------------------------------------------------------------
// FHE simulation helpers
// ---------------------------------------------------------------------------

func randomNonce() int {
	b := make([]byte, 2)
	_, _ = rand.Read(b)
	return int(b[0])<<8 | int(b[1])
}

func fheEncrypt(data []byte, nonce int) []byte {
	out := make([]byte, len(data))
	shift := byte(nonce & 0xFF)
	for i, b := range data {
		out[i] = b + shift
	}
	return out
}

func simulateTx() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return "0x" + hex.EncodeToString(b)
}
