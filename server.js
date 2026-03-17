// ExecDesk — Backend API Server
// This keeps your Anthropic API key safe on the server side.

const express = require('express');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 3000;

// Allow requests from your app and local testing
app.use(cors());
app.use(express.json());

// Health check — visit this URL to confirm the server is running
app.get('/', (req, res) => {
  res.json({ status: 'ExecDesk API is running' });
});

// Main AI chat endpoint — your app calls this
app.post('/api/chat', async (req, res) => {
  const { message, context } = req.body;

  if (!message) {
    return res.status(400).json({ error: 'Message is required' });
  }

  try {
    const response = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': process.env.ANTHROPIC_API_KEY,  // Stored safely as env variable
        'anthropic-version': '2023-06-01'
      },
      body: JSON.stringify({
        model: 'claude-sonnet-4-20250514',
        max_tokens: 1000,
        system: `You are an elite executive advisor and chief of staff. Be direct, concise, and actionable. No filler. Give specific recommendations. For well-being topics, be empathetic but practical. Context: ${context || ''}`,
        messages: [{ role: 'user', content: message }]
      })
    });

    const data = await response.json();

    if (data.error) {
      return res.status(500).json({ error: data.error.message });
    }

    const reply = data.content?.[0]?.text || 'No response received.';
    res.json({ reply });

  } catch (error) {
    console.error('API error:', error);
    res.status(500).json({ error: 'Failed to reach AI advisor. Please try again.' });
  }
});

app.listen(PORT, () => {
  console.log(`ExecDesk server running on port ${PORT}`);
});
