// ExecDesk — Phase 1 Backend
// Handles: Auth, Google Calendar sync, AI Advisor, Actions, Goals
// Deploy this to Render — never expose this file's secrets to the frontend

const express    = require('express');
const cors       = require('cors');
const { createClient } = require('@supabase/supabase-js');
const { google } = require('googleapis');

const app  = express();
const PORT = process.env.PORT || 3000;

// ── CLIENTS ──────────────────────────────────────────────────────────────────
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY  // service key — never sent to frontend
);

const oauth2Client = new google.auth.OAuth2(
  process.env.GOOGLE_CLIENT_ID,
  process.env.GOOGLE_CLIENT_SECRET,
  process.env.GOOGLE_REDIRECT_URI    // e.g. https://execdesk-api.onrender.com/auth/callback
);

// ── MIDDLEWARE ────────────────────────────────────────────────────────────────
app.use(cors({ origin: '*' }));
app.use(express.json());

// JWT auth middleware — protects all /api/* routes
async function requireAuth(req, res, next) {
  const token = req.headers.authorization?.replace('Bearer ', '');
  if (!token) return res.status(401).json({ error: 'No token provided' });

  const { data: { user }, error } = await supabase.auth.getUser(token);
  if (error || !user) return res.status(401).json({ error: 'Invalid token' });

  req.user = user;
  next();
}

// ── HEALTH CHECK ─────────────────────────────────────────────────────────────
app.get('/', (req, res) => {
  res.json({ status: 'ExecDesk API running', version: '1.0.0' });
});

// ── AUTH: GOOGLE OAUTH ───────────────────────────────────────────────────────

// Step 1 — App calls this to get the Google login URL
app.get('/auth/google/url', (req, res) => {
  const url = oauth2Client.generateAuthUrl({
    access_type: 'offline',
    prompt: 'consent',
    scope: [
      'https://www.googleapis.com/auth/calendar.readonly',
      'https://www.googleapis.com/auth/userinfo.email',
      'https://www.googleapis.com/auth/userinfo.profile',
    ]
  });
  res.json({ url });
});

// Step 2 — Google redirects here after user approves
app.get('/auth/callback', async (req, res) => {
  const { code } = req.query;
  if (!code) return res.redirect(`${process.env.APP_URL}?error=no_code`);

  try {
    // Exchange code for tokens
    const { tokens } = await oauth2Client.getToken(code);
    oauth2Client.setCredentials(tokens);

    // Get user profile from Google
    const oauth2 = google.oauth2({ version: 'v2', auth: oauth2Client });
    const { data: profile } = await oauth2.userinfo.get();

    // Sign in or create user in Supabase Auth
    const { data: authData, error: authError } = await supabase.auth.signInWithPassword({
      email: profile.email,
      password: process.env.SUPABASE_USERS_SECRET + profile.id // deterministic password
    }).catch(() => ({ data: null, error: 'not_found' }));

    let session;
    if (!authData?.session) {
      // User doesn't exist — create them
      const { data: signupData, error: signupError } = await supabase.auth.admin.createUser({
        email: profile.email,
        password: process.env.SUPABASE_USERS_SECRET + profile.id,
        email_confirm: true,
        user_metadata: { name: profile.name, avatar: profile.picture, google_id: profile.id }
      });
      if (signupError) throw signupError;

      const { data: signinData } = await supabase.auth.signInWithPassword({
        email: profile.email,
        password: process.env.SUPABASE_USERS_SECRET + profile.id
      });
      session = signinData?.session;
    } else {
      session = authData.session;
    }

    // Upsert user profile + store Google tokens in DB
    await supabase.from('users').upsert({
      id: session.user.id,
      email: profile.email,
      name: profile.name,
      avatar_url: profile.picture,
      google_access_token: tokens.access_token,
      google_refresh_token: tokens.refresh_token || null,
      google_token_expiry: tokens.expiry_date,
      updated_at: new Date().toISOString()
    }, { onConflict: 'id' });

    // Kick off first calendar sync in background
    syncCalendarForUser(session.user.id, tokens).catch(console.error);

    // Redirect back to app with session token
    res.redirect(`${process.env.APP_URL}?token=${session.access_token}&refresh=${session.refresh_token}`);

  } catch (err) {
    console.error('Auth callback error:', err);
    res.redirect(`${process.env.APP_URL}?error=auth_failed`);
  }
});

// Refresh a Supabase session token
app.post('/auth/refresh', async (req, res) => {
  const { refresh_token } = req.body;
  if (!refresh_token) return res.status(400).json({ error: 'refresh_token required' });

  const { data, error } = await supabase.auth.refreshSession({ refresh_token });
  if (error) return res.status(401).json({ error: 'Session expired. Please log in again.' });

  res.json({ token: data.session.access_token, refresh: data.session.refresh_token });
});

// Get current user profile
app.get('/auth/me', requireAuth, async (req, res) => {
  const { data, error } = await supabase
    .from('users')
    .select('id, email, name, avatar_url, timezone, role_title, subscription_tier')
    .eq('id', req.user.id)
    .single();

  if (error) return res.status(404).json({ error: 'User not found' });
  res.json(data);
});

// ── CALENDAR ─────────────────────────────────────────────────────────────────

// Helper: sync a user's Google Calendar events to Supabase cache
async function syncCalendarForUser(userId, tokens) {
  // Get fresh tokens from DB if not provided
  if (!tokens) {
    const { data: user } = await supabase
      .from('users')
      .select('google_access_token, google_refresh_token, google_token_expiry')
      .eq('id', userId)
      .single();
    if (!user?.google_refresh_token) return;
    tokens = {
      access_token: user.google_access_token,
      refresh_token: user.google_refresh_token,
      expiry_date: user.google_token_expiry
    };
  }

  oauth2Client.setCredentials(tokens);

  // Auto-refresh if expired
  if (tokens.expiry_date && Date.now() > tokens.expiry_date - 60000) {
    const { credentials } = await oauth2Client.refreshAccessToken();
    await supabase.from('users').update({
      google_access_token: credentials.access_token,
      google_token_expiry: credentials.expiry_date
    }).eq('id', userId);
    oauth2Client.setCredentials(credentials);
  }

  const calendar = google.calendar({ version: 'v3', auth: oauth2Client });

  // Fetch events from now to 14 days ahead
  const now  = new Date();
  const end  = new Date(now.getTime() + 14 * 24 * 60 * 60 * 1000);

  const { data } = await calendar.events.list({
    calendarId: 'primary',
    timeMin: now.toISOString(),
    timeMax: end.toISOString(),
    maxResults: 200,
    singleEvents: true,
    orderBy: 'startTime'
  });

  const events = (data.items || []).map(ev => {
    const title = ev.summary || '(No title)';
    // Travel detection: scan title and description for keywords
    const travelKeywords = ['flight', 'hotel', 'travel', 'airport', 'train', 'transit', 'airbnb', 'check-in', 'check in', 'fly', 'depart', 'arrive', 'layover'];
    const isTravel = travelKeywords.some(k => (title + (ev.description||'')).toLowerCase().includes(k));
    const attendees = (ev.attendees || []).map(a => ({ name: a.displayName || a.email, email: a.email }));
    const hasConference = !!(ev.conferenceData || ev.hangoutLink || (ev.description||'').match(/zoom\.us|teams\.microsoft|meet\.google/i));

    return {
      user_id: userId,
      google_event_id: ev.id,
      title,
      description: ev.description || null,
      start_time: ev.start?.dateTime || ev.start?.date,
      end_time: ev.end?.dateTime || ev.end?.date,
      location: ev.location || null,
      attendees,
      meeting_link: ev.hangoutLink || ev.conferenceData?.entryPoints?.[0]?.uri || null,
      is_all_day: !!ev.start?.date,
      is_travel: isTravel,
      is_virtual: hasConference,
      status: ev.status,
      updated_at: new Date().toISOString()
    };
  });

  // Upsert all events (insert or update by google_event_id)
  if (events.length > 0) {
    await supabase.from('calendar_events')
      .upsert(events, { onConflict: 'user_id,google_event_id' });
  }

  // Delete cached events that no longer exist in Google Calendar
  const googleIds = events.map(e => e.google_event_id);
  if (googleIds.length > 0) {
    await supabase.from('calendar_events')
      .delete()
      .eq('user_id', userId)
      .gte('start_time', now.toISOString())
      .not('google_event_id', 'in', `(${googleIds.map(id => `"${id}"`).join(',')})`);
  }

  return events;
}

// GET today's events
app.get('/api/calendar/today', requireAuth, async (req, res) => {
  // Trigger a background sync first
  syncCalendarForUser(req.user.id).catch(console.error);

  const todayStart = new Date(); todayStart.setHours(0,0,0,0);
  const todayEnd   = new Date(); todayEnd.setHours(23,59,59,999);

  const { data, error } = await supabase
    .from('calendar_events')
    .select('*')
    .eq('user_id', req.user.id)
    .gte('start_time', todayStart.toISOString())
    .lte('start_time', todayEnd.toISOString())
    .order('start_time', { ascending: true });

  if (error) return res.status(500).json({ error: error.message });
  res.json({ events: data || [], synced_at: new Date().toISOString() });
});

// GET week ahead events
app.get('/api/calendar/week', requireAuth, async (req, res) => {
  const start = new Date(); start.setHours(0,0,0,0);
  const end   = new Date(start.getTime() + 7 * 24 * 60 * 60 * 1000);

  const { data, error } = await supabase
    .from('calendar_events')
    .select('*')
    .eq('user_id', req.user.id)
    .gte('start_time', start.toISOString())
    .lte('start_time', end.toISOString())
    .order('start_time', { ascending: true });

  if (error) return res.status(500).json({ error: error.message });

  // Group by day and detect overload (4+ meetings in a day)
  const byDay = {};
  (data || []).forEach(ev => {
    const day = ev.start_time.slice(0, 10);
    if (!byDay[day]) byDay[day] = [];
    byDay[day].push(ev);
  });

  const days = Object.entries(byDay).map(([date, events]) => ({
    date,
    events,
    is_overloaded: events.filter(e => !e.is_all_day).length >= 4,
    travel_events: events.filter(e => e.is_travel),
    meeting_count: events.filter(e => !e.is_all_day && !e.is_travel).length
  }));

  res.json({ days, total_events: data?.length || 0 });
});

// GET travel events (next 30 days)
app.get('/api/calendar/travel', requireAuth, async (req, res) => {
  const start = new Date();
  const end   = new Date(start.getTime() + 30 * 24 * 60 * 60 * 1000);

  const { data, error } = await supabase
    .from('calendar_events')
    .select('*')
    .eq('user_id', req.user.id)
    .eq('is_travel', true)
    .gte('start_time', start.toISOString())
    .lte('start_time', end.toISOString())
    .order('start_time', { ascending: true });

  if (error) return res.status(500).json({ error: error.message });
  res.json({ travel: data || [] });
});

// Force sync (user taps refresh button)
app.post('/api/calendar/sync', requireAuth, async (req, res) => {
  try {
    const events = await syncCalendarForUser(req.user.id);
    res.json({ success: true, synced: events?.length || 0 });
  } catch (err) {
    res.status(500).json({ error: 'Sync failed: ' + err.message });
  }
});

// ── AI ADVISOR ────────────────────────────────────────────────────────────────

app.post('/api/chat', requireAuth, async (req, res) => {
  const { message } = req.body;
  if (!message) return res.status(400).json({ error: 'message required' });

  // Build rich context from user's real data
  const todayStart = new Date(); todayStart.setHours(0,0,0,0);
  const todayEnd   = new Date(); todayEnd.setHours(23,59,59,999);
  const weekEnd    = new Date(todayStart.getTime() + 7 * 24 * 60 * 60 * 1000);

  const [userRes, todayRes, weekRes, actionsRes, goalsRes, historyRes] = await Promise.all([
    supabase.from('users').select('name, role_title, timezone').eq('id', req.user.id).single(),
    supabase.from('calendar_events').select('title, start_time, end_time, attendees, is_travel').eq('user_id', req.user.id).gte('start_time', todayStart.toISOString()).lte('start_time', todayEnd.toISOString()).order('start_time'),
    supabase.from('calendar_events').select('title, start_time, is_travel').eq('user_id', req.user.id).gte('start_time', todayStart.toISOString()).lte('start_time', weekEnd.toISOString()).order('start_time'),
    supabase.from('action_items').select('title, due_date, status, delegated_to').eq('user_id', req.user.id).neq('status', 'done').order('due_date'),
    supabase.from('goals').select('title, progress_pct, target_date').eq('user_id', req.user.id).order('created_at'),
    supabase.from('ai_conversations').select('role, content').eq('user_id', req.user.id).order('created_at', { ascending: false }).limit(10)
  ]);

  const user = userRes.data;
  const todayEvents = todayRes.data || [];
  const weekEvents  = weekRes.data  || [];
  const actions     = actionsRes.data || [];
  const goals       = goalsRes.data || [];
  const history     = (historyRes.data || []).reverse();

  const todaySummary = todayEvents.map(e => `${new Date(e.start_time).toLocaleTimeString('en-US',{hour:'2-digit',minute:'2-digit'})} - ${e.title}${e.is_travel?' (TRAVEL)':''}`).join('\n') || 'No meetings today';
  const actionSummary = actions.slice(0,5).map(a => `- ${a.title} (due: ${a.due_date || 'no date'}${a.delegated_to ? ', delegated to '+a.delegated_to : ''})`).join('\n') || 'No open action items';
  const goalSummary = goals.map(g => `- ${g.title}: ${g.progress_pct}%`).join('\n') || 'No goals set';
  const overloadDays = weekEvents.reduce((acc, e) => { const d = e.start_time.slice(0,10); acc[d] = (acc[d]||0)+1; return acc; }, {});
  const busyDays = Object.entries(overloadDays).filter(([,c]) => c >= 4).map(([d]) => d).join(', ') || 'none';

  const context = `
Executive: ${user?.name || 'User'} — ${user?.role_title || 'CEO/Executive'}
Today (${new Date().toDateString()}):
${todaySummary}

Open actions (top 5):
${actionSummary}

Goals & progress:
${goalSummary}

Overloaded days this week (4+ meetings): ${busyDays}
Travel events this week: ${weekEvents.filter(e=>e.is_travel).map(e=>e.title).join(', ') || 'none'}
`.trim();

  // Save user message to history
  await supabase.from('ai_conversations').insert({ user_id: req.user.id, role: 'user', content: message });

  // Build conversation history for Claude
  const messages = [
    ...history.map(h => ({ role: h.role, content: h.content })),
    { role: 'user', content: message }
  ];

  try {
    const response = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': process.env.ANTHROPIC_API_KEY,
        'anthropic-version': '2023-06-01'
      },
      body: JSON.stringify({
        model: 'claude-sonnet-4-20250514',
        max_tokens: 1000,
        system: `You are an elite executive advisor and chief of staff. Be direct, concise, and actionable. No filler. Give specific, data-driven recommendations based on the executive's real schedule. For well-being topics, be empathetic but practical. Here is the executive's current context:\n\n${context}`,
        messages
      })
    });

    const data = await response.json();
    const reply = data.content?.[0]?.text || 'Unable to respond right now. Please try again.';

    // Save AI reply to history
    await supabase.from('ai_conversations').insert({ user_id: req.user.id, role: 'assistant', content: reply });

    res.json({ reply });
  } catch (err) {
    console.error('AI error:', err);
    res.status(500).json({ error: 'AI service unavailable' });
  }
});

// ── ACTION ITEMS ──────────────────────────────────────────────────────────────

app.get('/api/actions', requireAuth, async (req, res) => {
  const { data, error } = await supabase
    .from('action_items')
    .select('*')
    .eq('user_id', req.user.id)
    .order('due_date', { ascending: true, nullsLast: true });
  if (error) return res.status(500).json({ error: error.message });
  res.json({ actions: data || [] });
});

app.post('/api/actions', requireAuth, async (req, res) => {
  const { title, due_date, delegated_to, priority } = req.body;
  if (!title) return res.status(400).json({ error: 'title required' });

  const { data, error } = await supabase.from('action_items').insert({
    user_id: req.user.id, title, due_date: due_date || null,
    delegated_to: delegated_to || null, priority: priority || 'medium', status: 'pending'
  }).select().single();

  if (error) return res.status(500).json({ error: error.message });
  res.json({ action: data });
});

app.patch('/api/actions/:id', requireAuth, async (req, res) => {
  const { status, title, due_date } = req.body;
  const updates = {};
  if (status !== undefined) updates.status = status;
  if (title  !== undefined) updates.title  = title;
  if (due_date !== undefined) updates.due_date = due_date;
  updates.updated_at = new Date().toISOString();

  const { data, error } = await supabase.from('action_items')
    .update(updates).eq('id', req.params.id).eq('user_id', req.user.id).select().single();
  if (error) return res.status(500).json({ error: error.message });
  res.json({ action: data });
});

app.delete('/api/actions/:id', requireAuth, async (req, res) => {
  await supabase.from('action_items').delete().eq('id', req.params.id).eq('user_id', req.user.id);
  res.json({ success: true });
});

// ── GOALS ─────────────────────────────────────────────────────────────────────

app.get('/api/goals', requireAuth, async (req, res) => {
  const { data, error } = await supabase
    .from('goals').select('*').eq('user_id', req.user.id).order('created_at');
  if (error) return res.status(500).json({ error: error.message });
  res.json({ goals: data || [] });
});

app.post('/api/goals', requireAuth, async (req, res) => {
  const { title, target_date, progress_pct, notes } = req.body;
  if (!title) return res.status(400).json({ error: 'title required' });
  const { data, error } = await supabase.from('goals').insert({
    user_id: req.user.id, title, target_date: target_date || null,
    progress_pct: progress_pct || 0, notes: notes || null
  }).select().single();
  if (error) return res.status(500).json({ error: error.message });
  res.json({ goal: data });
});

app.patch('/api/goals/:id', requireAuth, async (req, res) => {
  const { progress_pct, title, notes } = req.body;
  const updates = { updated_at: new Date().toISOString() };
  if (progress_pct !== undefined) updates.progress_pct = progress_pct;
  if (title !== undefined) updates.title = title;
  if (notes !== undefined) updates.notes = notes;
  const { data, error } = await supabase.from('goals')
    .update(updates).eq('id', req.params.id).eq('user_id', req.user.id).select().single();
  if (error) return res.status(500).json({ error: error.message });
  res.json({ goal: data });
});

// ── USER SETTINGS ─────────────────────────────────────────────────────────────

app.patch('/api/settings', requireAuth, async (req, res) => {
  const { role_title, timezone, name } = req.body;
  const updates = { updated_at: new Date().toISOString() };
  if (role_title !== undefined) updates.role_title = role_title;
  if (timezone   !== undefined) updates.timezone   = timezone;
  if (name       !== undefined) updates.name       = name;
  const { data, error } = await supabase.from('users')
    .update(updates).eq('id', req.user.id).select().single();
  if (error) return res.status(500).json({ error: error.message });
  res.json({ user: data });
});

// ── START ─────────────────────────────────────────────────────────────────────
app.listen(PORT, () => console.log(`ExecDesk backend running on port ${PORT}`));
