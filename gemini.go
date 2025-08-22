package main

import (
	"context"
	"fmt"

	"github.com/google/generative-ai-go/genai"
	"google.golang.org/api/option"
)

type GeminiClient struct {
	client *genai.Client
	model  *genai.GenerativeModel
}

func NewGeminiClient(apiKey string) (*GeminiClient, error) {
	c, err := genai.NewClient(context.Background(), option.WithAPIKey(apiKey))
	if err != nil {
		return nil, err
	}
	return &GeminiClient{
		client: c,
		model:  c.GenerativeModel("gemini-1.5-flash"),
	}, nil
}

func (g *GeminiClient) Explain(ctx context.Context, normalizedJSON string) (string, error) {
	prompt := fmt.Sprintf(`Explain these anti-virus scan results for a non-technical user.
- Avoid jargon; be clear and concise.
- Provide a risk level (Low/Medium/High) and next steps.
- Note this is not a full security guarantee.

Results JSON:
%s`, normalizedJSON)

	resp, err := g.model.GenerateContent(ctx, genai.Text(prompt))
	if err != nil {
		return "", err
	}
	if len(resp.Candidates) == 0 || resp.Candidates[0] == nil {
		return "No explanation available yet.", nil
	}
	out := ""
	for _, p := range resp.Candidates[0].Content.Parts {
		out += fmt.Sprint(p)
	}
	return out, nil
}
