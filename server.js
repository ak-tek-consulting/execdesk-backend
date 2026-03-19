// ExecDesk — Phase 1 Backend (Auth Fix)
// Robust Google OAuth callback that handles all edge cases

const express    = require('express');
const cors       = require('cors');
const { createClient } = require('@supabase/supabase-js');
const { google } = require('googleapis');

const app  = express();
const PORT = process.env.PORT || 3000;

// ── CLIENTS ───────────────────────────────────────────────────────────────────
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY
);

const oauth2Client = new google.auth.OAuth2(
  process.env.GOOGLE_CLIENT_ID,
  process.env.GOOGLE_CLIENT_SECRET,
  process.env.GOOGLE_REDIRECT_URI
);

// ── MIDDLEWARE ────────────────────────────────────────────────────────────────
app.use(cors({ origin: '*' }));
app.use(express.json());

async function requireAuth(req, res, next) {
  const token = req.headers.authorization?.replace('Bearer ', '');
  if (!token) return res.status(401).json({ error: 'No token provided' });
  const { data: { user }, error } = await supabase.auth.getUser(token);
  if (error || !user) return res.status(401).json({ error: 'Invalid token' });
  req.user = user;
  next();
}

// ── HEALTH CHECK ──────────────────────────────────────────────────────────────
app.get('/', (req, res) => {
  res.json({ status: 'ExecDesk API running', version: '1.1.0' });
});

// ── AUTH ──────────────────────────────────────────────────────────────────────

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

// ── FIXED AUTH CALLBACK ───────────────────────────────────────────────────────
app.get('/auth/callback', async (req, res) => {
  const APP_URL = process.env.APP_URL || 'http://localhost';

  // Google may return an error (e.g. user cancelled)
  if (req.query.error) {
    console.error('[AUTH] Google returned error:', req.query.error);
    return res.redirect(`${APP_URL}?error=${encodeURIComponent(req.query.error)}`);
  }

  const { code } = req.query;
  if (!code) {
    console.error('[AUTH] No code in callback');
    return res.redirect(`${APP_URL}?error=no_code`);
  }

  try {
    // ── Step 1: Exchange code for Google tokens ───────────────────────────────
    console.log('[AUTH] Exchanging code for tokens...');
    const { tokens } = await oauth2Client.getToken(code);
    oauth2Client.setCredentials(tokens);
    console.log('[AUTH] Got Google tokens. Has refresh token:', !!tokens.refresh_token);

    // ── Step 2: Get Google profile ────────────────────────────────────────────
    console.log('[AUTH] Fetching Google profile...');
    const oauth2Api = google.oauth2({ version: 'v2', auth: oauth2Client });
    const { data: profile } = await oauth2Api.userinfo.get();
    console.log('[AUTH] Profile fetched:', profile.email);

    // ── Step 3: Get or create Supabase user ───────────────────────────────────
    const password = (process.env.SUPABASE_USERS_SECRET || 'default-secret') + profile.id;

    // First try signing in (user already exists)
    let session = null;
    console.log('[AUTH] Trying sign in...');
    const { data: signinData, error: signinError } = await supabase.auth.signInWithPassword({
      email: profile.email,
      password
    });

    if (signinData?.session) {
      // Existing user — signed in successfully
      session = signinData.session;
      console.log('[AUTH] Existing user signed in successfully');
    } else {
      // User not found — create them
      console.log('[AUTH] Sign in failed:', signinError?.message, '— creating new user...');

      const { data: createData, error: createError } = await supabase.auth.admin.createUser({
        email: profile.email,
        password,
        email_confirm: true,
        user_metadata: {
          name: profile.name,
          avatar_url: profile.picture,
          google_id: profile.id
        }
      });

      if (createError) {
        // User may already exist with different state — try sign in one more time
        if (createError.message?.includes('already been registered') || createError.message?.includes('already exists')) {
          console.log('[AUTH] User already exists, retrying sign in...');
          const { data: retryData, error: retryError } = await supabase.auth.signInWithPassword({
            email: profile.email, password
          });
          if (retryData?.session) {
            session = retryData.session;
            console.log('[AUTH] Retry sign in succeeded');
          } else {
            console.error('[AUTH] Retry sign in failed:', retryError?.message);
            throw new Error('Could not sign in: ' + (retryError?.message || 'unknown error'));
          }
        } else {
          console.error('[AUTH] Create user failed:', createError.message);
          throw new Error('Could not create user: ' + createError.message);
        }
      } else {
        // New user created — now sign in
        console.log('[AUTH] New user created:', createData?.user?.id);
        const { data: newSignin, error: newSigninError } = await supabase.auth.signInWithPassword({
          email: profile.email, password
        });
        if (newSignin?.session) {
          session = newSignin.session;
          console.log('[AUTH] New user signed in successfully');
        } else {
          console.error('[AUTH] New user sign in failed:', newSigninError?.message);
          throw new Error('Could not sign in new user: ' + (newSigninError?.message || 'no session'));
        }
      }
    }

    if (!session) {
      throw new Error('No session obtained after auth flow');
    }

    // ── Step 4: Save/update user profile + Google tokens in DB ───────────────
    console.log('[AUTH] Saving user profile to DB...');
    const { error: upsertError } = await supabase.from('users').upsert({
      id: session.user.id,
      email: profile.email,
      name: profile.name,
      avatar_url: profile.picture,
      google_access_token: tokens.access_token,
      google_refresh_token: tokens.refresh_token || null,
      google_token_expiry: tokens.expiry_date,
      updated_at: new Date().toISOString()
    }, { onConflict: 'id' });

    if (upsertError) {
      // Non-fatal — log it but continue
      console.warn('[AUTH] Profile upsert warning:', upsertError.message);
    }

    // ── Step 5: Kick off calendar sync in background ──────────────────────────
    console.log('[AUTH] Starting background calendar sync...');
    syncCalendarForUser(session.user.id, tokens).catch(e =>
      console.warn('[AUTH] Background sync warning:', e.message)
    );

    // ── Step 6: Redirect to app with tokens ───────────────────────────────────
    const redirectUrl = `${APP_URL}?token=${encodeURIComponent(session.access_token)}&refresh=${encodeURIComponent(session.refresh_token)}`;
    console.log('[AUTH] Redirecting to app. Token length:', session.access_token?.length);
    return res.redirect(redirectUrl);

  } catch (err) {
    console.error('[AUTH] Fatal error in callback:', err.message);
    return res.redirect(`${APP_URL}?error=${encodeURIComponent(err.message)}`);
  }
});

// Refresh session
app.post('/auth/refresh', async (req, res) => {
  const { refresh_token } = req.body;
  if (!refresh_token) return res.status(400).json({ error: 'refresh_token required' });
  const { data, error } = await supabase.auth.refreshSession({ refresh_token });
  if (error) return res.status(401).json({ error: 'Session expired. Please log in again.' });
  res.json({ token: data.session.access_token, refresh: data.session.refresh_token });
});

// Get current user
app.get('/auth/me', requireAuth, async (req, res) => {
  const { data, error } = await supabase
    .from('users')
    .select('id, email, name, avatar_url, timezone, role_title, subscription_tier')
    .eq('id', req.user.id)
    .single();
  if (error) {
    // User row may not exist yet (race condition) — return basic info from JWT
    return res.json({
      id: req.user.id,
      email: req.user.email,
      name: req.user.user_metadata?.name || req.user.email,
      avatar_url: req.user.user_metadata?.avatar_url || null,
      timezone: 'America/New_York',
      role_title: 'CEO',
      subscription_tier: 'free'
    });
  }
  res.json(data);
});

// ── CALENDAR ──────────────────────────────────────────────────────────────────

async function getAuthClient(userId) {
  const { data: user, error } = await supabase
    .from('users')
    .select('google_access_token, google_refresh_token, google_token_expiry')
    .eq('id', userId)
    .single();

  if (error || !user?.google_refresh_token) {
    throw new Error('No Google tokens found. Please reconnect your calendar.');
  }

  const client = new google.auth.OAuth2(
    process.env.GOOGLE_CLIENT_ID,
    process.env.GOOGLE_CLIENT_SECRET,
    process.env.GOOGLE_REDIRECT_URI
  );

  client.setCredentials({
    access_token: user.google_access_token,
    refresh_token: user.google_refresh_token,
    expiry_date: user.google_token_expiry
  });

  // Auto-refresh if token is expired or expiring in next 60 seconds
  if (user.google_token_expiry && Date.now() > user.google_token_expiry - 60000) {
    try {
      const { credentials } = await client.refreshAccessToken();
      await supabase.from('users').update({
        google_access_token: credentials.access_token,
        google_token_expiry: credentials.expiry_date
      }).eq('id', userId);
      client.setCredentials(credentials);
      console.log('[CALENDAR] Token refreshed for user:', userId);
    } catch (e) {
      console.warn('[CALENDAR] Token refresh failed:', e.message);
    }
  }

  return client;
}

async function syncCalendarForUser(userId, tokens) {
  let authClient;
  if (tokens) {
    authClient = new google.auth.OAuth2(
      process.env.GOOGLE_CLIENT_ID,
      process.env.GOOGLE_CLIENT_SECRET,
      process.env.GOOGLE_REDIRECT_URI
    );
    authClient.setCredentials(tokens);
  } else {
    authClient = await getAuthClient(userId);
  }

  const calendar = google.calendar({ version: 'v3', auth: authClient });
  const now = new Date();
  const end = new Date(now.getTime() + 14 * 24 * 60 * 60 * 1000);

  const { data } = await calendar.events.list({
    calendarId: 'primary',
    timeMin: now.toISOString(),
    timeMax: end.toISOString(),
    maxResults: 200,
    singleEvents: true,
    orderBy: 'startTime'
  });

  const travelKeywords = ['flight', 'hotel', 'travel', 'airport', 'train', 'airbnb', 'check-in', 'check in', 'fly', 'depart', 'arrive', 'layover', 'uber', 'lyft', 'taxi'];

  const events = (data.items || []).map(ev => {
    const title = ev.summary || '(No title)';
    const desc  = ev.description || '';
    const isTravel   = travelKeywords.some(k => (title + desc).toLowerCase().includes(k));
    const isVirtual  = !!(ev.conferenceData || ev.hangoutLink || desc.match(/zoom\.us|teams\.microsoft|meet\.google/i));
    const attendees  = (ev.attendees || []).map(a => ({ name: a.displayName || a.email, email: a.email }));

    return {
      user_id: userId,
      google_event_id: ev.id,
      title,
      description: desc || null,
      start_time: ev.start?.dateTime || ev.start?.date,
      end_time:   ev.end?.dateTime   || ev.end?.date,
      location:   ev.location || null,
      attendees,
      meeting_link: ev.hangoutLink || ev.conferenceData?.entryPoints?.[0]?.uri || null,
      is_all_day:  !!ev.start?.date,
      is_travel:   isTravel,
      is_virtual:  isVirtual,
      status:      ev.status,
      updated_at:  new Date().toISOString()
    };
  });

  if (events.length > 0) {
    const { error } = await supabase.from('calendar_events')
      .upsert(events, { onConflict: 'user_id,google_event_id' });
    if (error) console.error('[CALENDAR] Upsert error:', error.message);
  }

  console.log(`[CALENDAR] Synced ${events.length} events for user ${userId}`);
  return events;
}

app.get('/api/calendar/today', requireAuth, async (req, res) => {
  syncCalendarForUser(req.user.id).catch(e => console.warn('[SYNC]', e.message));

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

  const user       = userRes.data || {};
  const todayEvs   = todayRes.data || [];
  const weekEvs    = weekRes.data  || [];
  const actions    = actionsRes.data || [];
  const goals      = goalsRes.data   || [];
  const history    = (historyRes.data || []).reverse();

  const fmt = iso => new Date(iso).toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' });

  const todaySummary  = todayEvs.map(e => `  ${fmt(e.start_time)} - ${e.title}${e.is_travel ? ' [TRAVEL]' : ''}`).join('\n') || '  No meetings today';
  const actionSummary = actions.slice(0,5).map(a => `  - ${a.title} (due: ${a.due_date || 'no date'}${a.delegated_to ? ', delegated to ' + a.delegated_to : ''})`).join('\n') || '  No open actions';
  const goalSummary   = goals.map(g => `  - ${g.title}: ${g.progress_pct}%`).join('\n') || '  No goals set';
  const overloadDays  = Object.entries(weekEvs.reduce((a,e) => { const d=e.start_time.slice(0,10); a[d]=(a[d]||0)+1; return a; }, {})).filter(([,c])=>c>=4).map(([d])=>d).join(', ') || 'none';

  const context = `Executive: ${user.name || req.user.email} — ${user.role_title || 'CEO/Executive'}
Today (${new Date().toDateString()}):
${todaySummary}

Open action items:
${actionSummary}

Goals & OKR progress:
${goalSummary}

Overloaded days this week (4+ meetings): ${overloadDays}
Travel events detected: ${weekEvs.filter(e=>e.is_travel).map(e=>e.title).join(', ') || 'none'}`;

  await supabase.from('ai_conversations').insert({ user_id: req.user.id, role: 'user', content: message });

  const messages = [
    ...history.map(h => ({ role: h.role, content: h.content })),
    { role: 'user', content: message }
  ];

  try {
    const r = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'x-api-key': process.env.ANTHROPIC_API_KEY, 'anthropic-version': '2023-06-01' },
      body: JSON.stringify({
        model: 'claude-sonnet-4-20250514',
        max_tokens: 1000,
        system: `You are an elite executive advisor and chief of staff. Be direct, concise, and actionable. No filler. Use the executive's real schedule data to give specific recommendations. Context:\n\n${context}`,
        messages
      })
    });
    const data  = await r.json();
    const reply = data.content?.[0]?.text || 'Unable to respond right now.';
    await supabase.from('ai_conversations').insert({ user_id: req.user.id, role: 'assistant', content: reply });
    res.json({ reply });
  } catch (err) {
    console.error('[AI] Error:', err.message);
    res.status(500).json({ error: 'AI service unavailable' });
  }
});

// ── ACTIONS ───────────────────────────────────────────────────────────────────
app.get('/api/actions', requireAuth, async (req, res) => {
  const { data, error } = await supabase.from('action_items').select('*').eq('user_id', req.user.id).order('due_date', { ascending: true, nullsLast: true });
  if (error) return res.status(500).json({ error: error.message });
  res.json({ actions: data || [] });
});

app.post('/api/actions', requireAuth, async (req, res) => {
  const { title, due_date, delegated_to, priority } = req.body;
  if (!title) return res.status(400).json({ error: 'title required' });
  const { data, error } = await supabase.from('action_items').insert({ user_id: req.user.id, title, due_date: due_date || null, delegated_to: delegated_to || null, priority: priority || 'medium', status: 'pending' }).select().single();
  if (error) return res.status(500).json({ error: error.message });
  res.json({ action: data });
});

app.patch('/api/actions/:id', requireAuth, async (req, res) => {
  const updates = { updated_at: new Date().toISOString() };
  ['status','title','due_date'].forEach(k => { if (req.body[k] !== undefined) updates[k] = req.body[k]; });
  const { data, error } = await supabase.from('action_items').update(updates).eq('id', req.params.id).eq('user_id', req.user.id).select().single();
  if (error) return res.status(500).json({ error: error.message });
  res.json({ action: data });
});

app.delete('/api/actions/:id', requireAuth, async (req, res) => {
  await supabase.from('action_items').delete().eq('id', req.params.id).eq('user_id', req.user.id);
  res.json({ success: true });
});

// ── GOALS ─────────────────────────────────────────────────────────────────────
app.get('/api/goals', requireAuth, async (req, res) => {
  const { data, error } = await supabase.from('goals').select('*').eq('user_id', req.user.id).order('created_at');
  if (error) return res.status(500).json({ error: error.message });
  res.json({ goals: data || [] });
});

app.post('/api/goals', requireAuth, async (req, res) => {
  const { title, target_date, progress_pct, notes } = req.body;
  if (!title) return res.status(400).json({ error: 'title required' });
  const { data, error } = await supabase.from('goals').insert({ user_id: req.user.id, title, target_date: target_date || null, progress_pct: progress_pct || 0, notes: notes || null }).select().single();
  if (error) return res.status(500).json({ error: error.message });
  res.json({ goal: data });
});

app.patch('/api/goals/:id', requireAuth, async (req, res) => {
  const updates = { updated_at: new Date().toISOString() };
  ['progress_pct','title','notes'].forEach(k => { if (req.body[k] !== undefined) updates[k] = req.body[k]; });
  const { data, error } = await supabase.from('goals').update(updates).eq('id', req.params.id).eq('user_id', req.user.id).select().single();
  if (error) return res.status(500).json({ error: error.message });
  res.json({ goal: data });
});

// ── SETTINGS ──────────────────────────────────────────────────────────────────
app.patch('/api/settings', requireAuth, async (req, res) => {
  const updates = { updated_at: new Date().toISOString() };
  ['role_title','timezone','name'].forEach(k => { if (req.body[k] !== undefined) updates[k] = req.body[k]; });
  const { data, error } = await supabase.from('users').update(updates).eq('id', req.user.id).select().single();
  if (error) return res.status(500).json({ error: error.message });
  res.json({ user: data });
});

// ── START ─────────────────────────────────────────────────────────────────────
app.listen(PORT, () => console.log(`ExecDesk backend running on port ${PORT}`));
