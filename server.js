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

      const { data: signinData, error: signinError } = await supabase.auth.signInWithPassword({
        email: profile.email,
        password: process.env.SUPABASE_USERS_SECRET + profile.id
      });
      if (signinError || !signinData?.session) {
        throw new Error(`Post-signup sign-in failed: ${signinError?.message || 'no session returned'}`);
      }
      session = signinData.session;
    } else {
      session = authData.session;
    }

    // Guard: prevents ?token=undefined reaching the frontend
    if (!session?.access_token || !session?.refresh_token) {
      throw new Error('Session tokens missing after authentication');
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

// Helper: build an authenticated OAuth2 client for a given user.
// Fetches tokens from Supabase, refreshes if expired, and returns the client.
async function getAuthClient(userId) {
  const { data: user, error } = await supabase
    .from('users')
    .select('google_access_token, google_refresh_token, google_token_expiry')
    .eq('id', userId)
    .single();

  if (error || !user?.google_refresh_token) {
    throw new Error('No Google credentials found for user. Please reconnect your Google account.');
  }

  const tokens = {
    access_token:  user.google_access_token,
    refresh_token: user.google_refresh_token,
    expiry_date:   user.google_token_expiry
  };

  // Create a fresh client instance so concurrent requests don't clobber each other
  const authClient = new google.auth.OAuth2(
    process.env.GOOGLE_CLIENT_ID,
    process.env.GOOGLE_CLIENT_SECRET,
    process.env.GOOGLE_REDIRECT_URI
  );
  authClient.setCredentials(tokens);

  // Auto-refresh if the access token is expired or about to expire (within 60s)
  if (tokens.expiry_date && Date.now() > tokens.expiry_date - 60000) {
    const { credentials } = await authClient.refreshAccessToken();
    await supabase.from('users').update({
      google_access_token: credentials.access_token,
      google_token_expiry: credentials.expiry_date
    }).eq('id', userId);
    authClient.setCredentials(credentials);
  }

  return authClient;
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
// ═══════════════════════════════════════════════════════════════════════════
// PAST MEETINGS HISTORY ROUTES — Fixed version
//
// PASTE LOCATION: In server.js, paste this AFTER the syncCalendarForUser
// function and AFTER the /api/calendar/sync route. It must come AFTER
// getAuthClient is defined (around line 222 in your server.js).
//
// QUICK CHECK: Search your server.js for "async function getAuthClient"
// The code below must appear AFTER that function definition.
// ═══════════════════════════════════════════════════════════════════════════


// ── /api/calendar/history ─────────────────────────────────────────────────────
// Fetches past calendar events. Checks Supabase cache first.
// If cache is empty for the range, fetches from Google Calendar API.
// ?start=YYYY-MM-DD&end=YYYY-MM-DD

app.get('/api/calendar/history', requireAuth, async (req, res) => {
  const { start, end } = req.query;

  if (!start || !end) {
    return res.status(400).json({ error: 'start and end params required (YYYY-MM-DD)' });
  }

  const startDate = new Date(start);
  const endDate   = new Date(end);
  endDate.setHours(23, 59, 59, 999);

  if (isNaN(startDate.getTime()) || isNaN(endDate.getTime())) {
    return res.status(400).json({ error: 'Invalid date format. Use YYYY-MM-DD.' });
  }

  const diffDays = (endDate - startDate) / (1000 * 60 * 60 * 24);
  if (diffDays > 90) {
    return res.status(400).json({ error: 'Date range cannot exceed 90 days' });
  }

  const travelKeywords = ['flight','hotel','travel','airport','train','airbnb',
    'check-in','check in','fly','depart','arrive','layover'];

  // ── Step 1: Check Supabase cache ──────────────────────────────────────────
  try {
    const { data: cached, error: cacheErr } = await supabase
      .from('calendar_events')
      .select('*')
      .eq('user_id', req.user.id)
      .gte('start_time', startDate.toISOString())
      .lte('start_time', endDate.toISOString())
      .order('start_time', { ascending: true });

    if (cacheErr) {
      console.warn('[HISTORY] Cache read error:', cacheErr.message);
    } else if (cached && cached.length > 0) {
      console.log(`[HISTORY] Cache hit: ${cached.length} events for ${start} → ${end}`);
      return res.json({ events: cached, source: 'cache', total: cached.length });
    }
  } catch (cacheEx) {
    console.warn('[HISTORY] Cache exception:', cacheEx.message);
  }

  // ── Step 2: Fetch from Google Calendar API ────────────────────────────────
  // getAuthClient is defined in server.js — this must be pasted AFTER it.
  let googleEvents = [];
  let fetchedFromGoogle = false;

  try {
    // This is the line that was failing — getAuthClient must exist in scope.
    // If you see "getAuthClient is not defined", move this paste location
    // to AFTER the getAuthClient function in server.js.
    const authClient = await getAuthClient(req.user.id);

    // google is the googleapis require at the top of server.js:
    // const { google } = require('googleapis');
    const calendar = google.calendar({ version: 'v3', auth: authClient });

    const { data } = await calendar.events.list({
      calendarId:   'primary',
      timeMin:      startDate.toISOString(),
      timeMax:      endDate.toISOString(),
      maxResults:   500,
      singleEvents: true,
      orderBy:      'startTime'
    });

    googleEvents = (data.items || []).map(ev => {
      const title = ev.summary || '(No title)';
      const desc  = ev.description || '';
      const isTravel  = travelKeywords.some(k => (title + desc).toLowerCase().includes(k));
      const isVirtual = !!(
        ev.conferenceData || ev.hangoutLink ||
        desc.match(/zoom\.us|teams\.microsoft|meet\.google/i)
      );
      const attendees = (ev.attendees || []).map(a => ({
        name:  a.displayName || a.email,
        email: a.email
      }));

      return {
        user_id:         req.user.id,
        google_event_id: ev.id,
        title,
        description:     desc || null,
        start_time:      ev.start?.dateTime || ev.start?.date,
        end_time:        ev.end?.dateTime   || ev.end?.date,
        location:        ev.location || null,
        attendees,
        meeting_link:    ev.hangoutLink || ev.conferenceData?.entryPoints?.[0]?.uri || null,
        is_all_day:      !!ev.start?.date && !ev.start?.dateTime,
        is_travel:       isTravel,
        is_virtual:      isVirtual,
        status:          ev.status || 'confirmed',
        updated_at:      new Date().toISOString()
      };
    });

    fetchedFromGoogle = true;
    console.log(`[HISTORY] Fetched ${googleEvents.length} events from Google for ${start} → ${end}`);

    // Cache in Supabase for next time
    if (googleEvents.length > 0) {
      const { error: upsertErr } = await supabase
        .from('calendar_events')
        .upsert(googleEvents, { onConflict: 'user_id,google_event_id' });
      if (upsertErr) {
        console.warn('[HISTORY] Upsert warning (non-fatal):', upsertErr.message);
      }
    }

    return res.json({
      events: googleEvents,
      source: 'google',
      total:  googleEvents.length
    });

  } catch (googleErr) {
    // Google fetch failed — log it and fall through to empty response
    console.error('[HISTORY] Google Calendar fetch failed:', googleErr.message);

    // One more try: maybe cache was written by another request in the meantime
    try {
      const { data: fallback } = await supabase
        .from('calendar_events')
        .select('*')
        .eq('user_id', req.user.id)
        .gte('start_time', startDate.toISOString())
        .lte('start_time', endDate.toISOString())
        .order('start_time', { ascending: true });

      if (fallback && fallback.length > 0) {
        console.log(`[HISTORY] Fallback cache: ${fallback.length} events`);
        return res.json({ events: fallback, source: 'cache_fallback', total: fallback.length });
      }
    } catch (_) {}

    // Nothing worked — return the error so the frontend can show it
    return res.status(500).json({
      error: `Could not load history: ${googleErr.message}. ` +
             `If this is "getAuthClient is not defined", paste this code ` +
             `AFTER the getAuthClient function in server.js.`
    });
  }
});


// ── /api/calendar/search ──────────────────────────────────────────────────────
// Search cached events by title, description, or attendee name
// ?q=search+term&limit=50

app.get('/api/calendar/search', requireAuth, async (req, res) => {
  const { q, limit = 50 } = req.query;

  if (!q || q.trim().length < 2) {
    return res.status(400).json({ error: 'Search query must be at least 2 characters' });
  }

  const term = q.trim();

  try {
    // Search by title
    const { data: byTitle, error: e1 } = await supabase
      .from('calendar_events')
      .select('*')
      .eq('user_id', req.user.id)
      .ilike('title', `%${term}%`)
      .order('start_time', { ascending: false })
      .limit(parseInt(limit));

    if (e1) return res.status(500).json({ error: e1.message });

    // Search by description
    const { data: byDesc } = await supabase
      .from('calendar_events')
      .select('*')
      .eq('user_id', req.user.id)
      .ilike('description', `%${term}%`)
      .order('start_time', { ascending: false })
      .limit(20);

    // Deduplicate by id
    const seen = new Set();
    const merged = [...(byTitle || []), ...(byDesc || [])]
      .filter(ev => { if (seen.has(ev.id)) return false; seen.add(ev.id); return true; })
      .sort((a, b) => new Date(b.start_time) - new Date(a.start_time))
      .slice(0, parseInt(limit));

    // Also search attendees in memory (JSONB search varies by Supabase version)
    const termLower = term.toLowerCase();
    const { data: allCached } = await supabase
      .from('calendar_events')
      .select('*')
      .eq('user_id', req.user.id)
      .order('start_time', { ascending: false })
      .limit(500);

    const attMatches = (allCached || []).filter(ev => {
      if (seen.has(ev.id)) return false;
      return JSON.stringify(ev.attendees || []).toLowerCase().includes(termLower);
    }).slice(0, 20);

    attMatches.forEach(ev => seen.add(ev.id));

    const results = [...merged, ...attMatches]
      .sort((a, b) => new Date(b.start_time) - new Date(a.start_time))
      .slice(0, parseInt(limit));

    console.log(`[SEARCH] "${term}" → ${results.length} results`);
    res.json({ results, query: q, total: results.length });

  } catch (err) {
    console.error('[SEARCH] Error:', err.message);
    res.status(500).json({ error: 'Search failed: ' + err.message });
  }
});


// ── /api/calendar/month-summary ───────────────────────────────────────────────
// Aggregated stats for a given month
// ?year=2026&month=3

app.get('/api/calendar/month-summary', requireAuth, async (req, res) => {
  const year  = parseInt(req.query.year  || new Date().getFullYear());
  const month = parseInt(req.query.month || new Date().getMonth() + 1);

  const start = new Date(year, month - 1, 1);
  const end   = new Date(year, month, 0, 23, 59, 59, 999);

  const { data, error } = await supabase
    .from('calendar_events')
    .select('title, start_time, end_time, is_all_day, is_travel, is_virtual, attendees')
    .eq('user_id', req.user.id)
    .gte('start_time', start.toISOString())
    .lte('start_time', end.toISOString())
    .order('start_time', { ascending: true });

  if (error) return res.status(500).json({ error: error.message });

  const events   = data || [];
  const meetings = events.filter(e => !e.is_all_day && !e.is_travel);
  const travel   = events.filter(e => e.is_travel);
  const totalMin = meetings.reduce((a, e) => {
    const dur = (new Date(e.end_time) - new Date(e.start_time)) / 60000;
    return a + (isNaN(dur) ? 0 : dur);
  }, 0);

  const peopleSet = new Set();
  meetings.forEach(e => (e.attendees || []).forEach(a => a.email && peopleSet.add(a.email)));

  const byDay = {};
  meetings.forEach(e => {
    const d = e.start_time.slice(0, 10);
    byDay[d] = (byDay[d] || 0) + 1;
  });
  const busiestDay = Object.entries(byDay).sort(([,a],[,b]) => b - a)[0];

  res.json({
    month:               `${year}-${String(month).padStart(2,'0')}`,
    total_events:        events.length,
    total_meetings:      meetings.length,
    total_travel:        travel.length,
    total_meeting_hours: Math.round(totalMin / 60 * 10) / 10,
    unique_attendees:    peopleSet.size,
    busiest_day:         busiestDay ? { date: busiestDay[0], count: busiestDay[1] } : null,
    virtual_meetings:    meetings.filter(e => e.is_virtual).length
  });
});

app.get('/api/calendar/history', requireAuth, async (req, res) => {
  const { start, end } = req.query;

  if (!start || !end) {
    return res.status(400).json({ error: 'start and end query params required (YYYY-MM-DD)' });
  }

  const startDate = new Date(start);
  const endDate   = new Date(end);
  endDate.setHours(23, 59, 59, 999);

  // Cap range at 90 days to avoid Google API quota issues
  const diffDays = (endDate - startDate) / (1000 * 60 * 60 * 24);
  if (diffDays > 90) {
    return res.status(400).json({ error: 'Date range cannot exceed 90 days' });
  }
  if (startDate > new Date()) {
    return res.status(400).json({ error: 'start date must be in the past' });
  }

  try {
    // First check Supabase cache for this range
    const { data: cached } = await supabase
      .from('calendar_events')
      .select('*')
      .eq('user_id', req.user.id)
      .gte('start_time', startDate.toISOString())
      .lte('start_time', endDate.toISOString())
      .order('start_time', { ascending: true });

    // If we have cached data and it's reasonably complete, return it
    // (We consider cache valid if there are any events — historical events don't change)
    if (cached && cached.length > 0) {
      console.log(`[HISTORY] Returning ${cached.length} cached events for ${start} → ${end}`);
      return res.json({
        events: cached,
        source: 'cache',
        total: cached.length
      });
    }

    // No cache — fetch from Google Calendar API
    console.log(`[HISTORY] Fetching from Google Calendar API: ${start} → ${end}`);

    const authClient = await getAuthClient(req.user.id);
    const calendar   = google.calendar({ version: 'v3', auth: authClient });

    const { data } = await calendar.events.list({
      calendarId:   'primary',
      timeMin:      startDate.toISOString(),
      timeMax:      endDate.toISOString(),
      maxResults:   500,
      singleEvents: true,
      orderBy:      'startTime'
    });

    const travelKeywords = ['flight','hotel','travel','airport','train','airbnb','check-in','check in','fly','depart','arrive','layover'];

    const events = (data.items || []).map(ev => {
      const title = ev.summary || '(No title)';
      const desc  = ev.description || '';
      const isTravel  = travelKeywords.some(k => (title + desc).toLowerCase().includes(k));
      const isVirtual = !!(ev.conferenceData || ev.hangoutLink || desc.match(/zoom\.us|teams\.microsoft|meet\.google/i));
      const attendees = (ev.attendees || []).map(a => ({ name: a.displayName || a.email, email: a.email }));

      return {
        user_id:        req.user.id,
        google_event_id: ev.id,
        title,
        description:    desc || null,
        start_time:     ev.start?.dateTime || ev.start?.date,
        end_time:       ev.end?.dateTime   || ev.end?.date,
        location:       ev.location || null,
        attendees,
        meeting_link:   ev.hangoutLink || ev.conferenceData?.entryPoints?.[0]?.uri || null,
        is_all_day:     !!ev.start?.date,
        is_travel:      isTravel,
        is_virtual:     isVirtual,
        status:         ev.status,
        updated_at:     new Date().toISOString()
      };
    });

    // Cache the results in Supabase for future requests
    if (events.length > 0) {
      const { error: upsertError } = await supabase
        .from('calendar_events')
        .upsert(events, { onConflict: 'user_id,google_event_id' });

      if (upsertError) {
        console.warn('[HISTORY] Cache upsert warning:', upsertError.message);
      }
    }

    console.log(`[HISTORY] Fetched and cached ${events.length} events`);
    res.json({ events, source: 'google', total: events.length });

  } catch (err) {
    console.error('[HISTORY] Error:', err.message);

    // If Google API fails, try returning whatever is in cache as fallback
    const { data: fallback } = await supabase
      .from('calendar_events')
      .select('*')
      .eq('user_id', req.user.id)
      .gte('start_time', startDate.toISOString())
      .lte('start_time', endDate.toISOString())
      .order('start_time', { ascending: true });

    if (fallback && fallback.length > 0) {
      return res.json({ events: fallback, source: 'cache_fallback', total: fallback.length });
    }

    res.status(500).json({ error: 'Could not fetch history: ' + err.message });
  }
});


// ── SEARCH PAST MEETINGS ──────────────────────────────────────────────────────
// Full-text search across cached events (title, description, attendees)
// Accepts: ?q=search+term&limit=50

app.get('/api/calendar/search', requireAuth, async (req, res) => {
  const { q, limit = 50 } = req.query;

  if (!q || q.trim().length < 2) {
    return res.status(400).json({ error: 'Search query must be at least 2 characters' });
  }

  const searchTerm = q.trim().toLowerCase();

  try {
    // Search in title and description using Supabase ilike (case-insensitive)
    // We search across all cached events (both past and future)
    const { data: byTitle, error: e1 } = await supabase
      .from('calendar_events')
      .select('*')
      .eq('user_id', req.user.id)
      .ilike('title', `%${searchTerm}%`)
      .order('start_time', { ascending: false })
      .limit(parseInt(limit));

    const { data: byDesc } = await supabase
      .from('calendar_events')
      .select('*')
      .eq('user_id', req.user.id)
      .ilike('description', `%${searchTerm}%`)
      .order('start_time', { ascending: false })
      .limit(20);

    if (e1) return res.status(500).json({ error: e1.message });

    // Merge and deduplicate results
    const seen = new Set();
    const merged = [...(byTitle || []), ...(byDesc || [])]
      .filter(ev => {
        if (seen.has(ev.id)) return false;
        seen.add(ev.id);
        return true;
      })
      .sort((a, b) => new Date(b.start_time) - new Date(a.start_time))
      .slice(0, parseInt(limit));

    // Also search attendee names (in memory since JSONB search varies)
    const allCached = await supabase
      .from('calendar_events')
      .select('*')
      .eq('user_id', req.user.id)
      .order('start_time', { ascending: false })
      .limit(500);

    const attendeeMatches = (allCached.data || []).filter(ev => {
      if (seen.has(ev.id)) return false;
      const attendeeStr = JSON.stringify(ev.attendees || '').toLowerCase();
      return attendeeStr.includes(searchTerm);
    }).slice(0, 20);

    attendeeMatches.forEach(ev => seen.add(ev.id));

    const results = [...merged, ...attendeeMatches]
      .sort((a, b) => new Date(b.start_time) - new Date(a.start_time))
      .slice(0, parseInt(limit));

    console.log(`[SEARCH] "${searchTerm}" → ${results.length} results`);
    res.json({ results, query: q, total: results.length });

  } catch (err) {
    console.error('[SEARCH] Error:', err.message);
    res.status(500).json({ error: 'Search failed: ' + err.message });
  }
});


// ── SINGLE EVENT DETAIL ───────────────────────────────────────────────────────
// Fetch full details of a single cached event by its google_event_id
// Used when user clicks a meeting to see full details

app.get('/api/calendar/event/:eventId', requireAuth, async (req, res) => {
  const { data, error } = await supabase
    .from('calendar_events')
    .select('*')
    .eq('user_id', req.user.id)
    .eq('google_event_id', req.params.eventId)
    .single();

  if (error || !data) {
    return res.status(404).json({ error: 'Event not found' });
  }
  res.json({ event: data });
});


// ── MONTH SUMMARY ─────────────────────────────────────────────────────────────
// Returns aggregated stats for a given month
// Accepts: ?year=2026&month=3 (1-indexed month)

app.get('/api/calendar/month-summary', requireAuth, async (req, res) => {
  const year  = parseInt(req.query.year  || new Date().getFullYear());
  const month = parseInt(req.query.month || new Date().getMonth() + 1);

  const start = new Date(year, month - 1, 1);
  const end   = new Date(year, month, 0, 23, 59, 59, 999); // last day of month

  const { data, error } = await supabase
    .from('calendar_events')
    .select('title, start_time, end_time, is_all_day, is_travel, is_virtual, attendees')
    .eq('user_id', req.user.id)
    .gte('start_time', start.toISOString())
    .lte('start_time', end.toISOString())
    .order('start_time', { ascending: true });

  if (error) return res.status(500).json({ error: error.message });

  const events = data || [];
  const meetings = events.filter(e => !e.is_all_day && !e.is_travel);
  const travel   = events.filter(e => e.is_travel);
  const totalMin = meetings.reduce((a, e) => a + (new Date(e.end_time) - new Date(e.start_time)) / 60000, 0);

  // Unique attendees
  const attendeeSet = new Set();
  meetings.forEach(e => (e.attendees || []).forEach(a => a.email && attendeeSet.add(a.email)));

  // Busiest day
  const byDay = {};
  meetings.forEach(e => {
    const d = e.start_time.slice(0, 10);
    byDay[d] = (byDay[d] || 0) + 1;
  });
  const busiestDay = Object.entries(byDay).sort(([,a],[,b]) => b - a)[0];

  res.json({
    month: `${year}-${String(month).padStart(2,'0')}`,
    total_events: events.length,
    total_meetings: meetings.length,
    total_travel: travel.length,
    total_meeting_hours: Math.round(totalMin / 60 * 10) / 10,
    unique_attendees: attendeeSet.size,
    busiest_day: busiestDay ? { date: busiestDay[0], count: busiestDay[1] } : null,
    virtual_meetings: meetings.filter(e => e.is_virtual).length
  });
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
// ═══════════════════════════════════════════════════════════════════════════
// ExecDesk v4 — Backend Additions
// Add these routes to your existing server.js
// Paste AFTER the existing /api/calendar/sync route
// ═══════════════════════════════════════════════════════════════════════════

// ── NEW ENV VARIABLES NEEDED (add to Render) ──────────────────────────────
// MICROSOFT_CLIENT_ID     — from Azure App Registration
// MICROSOFT_CLIENT_SECRET — from Azure App Registration
// MICROSOFT_REDIRECT_URI  — https://execdesk-api.onrender.com/auth/microsoft/callback
// GOOGLE_REDIRECT_URI must also allow calendar write scope (update existing cred)
// ─────────────────────────────────────────────────────────────────────────

// ── UPDATE: Change Google Calendar scope to allow writes ──────────────────
// In your existing /auth/google/url route, change:
//   'https://www.googleapis.com/auth/calendar.readonly'
// To:
//   'https://www.googleapis.com/auth/calendar.events'
// This allows the agentic AI to actually move/update calendar events.
// Users will need to re-authorize (revoke at myaccount.google.com/permissions first)


// ═══════════════════════════════════════════════════════════════════════════
// FEATURE 1 — AGENTIC AI
// Analyzes the user's calendar and returns structured action proposals.
// Semi-auto: low-risk actions execute immediately, high-risk need approval.
// ═══════════════════════════════════════════════════════════════════════════

// Analyze calendar and generate action proposals
app.post('/api/agent/analyze', requireAuth, async (req, res) => {
  try {
    // Fetch next 7 days of events
    const now   = new Date(); now.setHours(0,0,0,0);
    const week  = new Date(now.getTime() + 7 * 86400000);
    const { data: events } = await supabase
      .from('calendar_events')
      .select('*')
      .eq('user_id', req.user.id)
      .gte('start_time', now.toISOString())
      .lte('start_time', week.toISOString())
      .order('start_time', { ascending: true });

    const { data: actions } = await supabase
      .from('action_items')
      .select('title, due_date, status')
      .eq('user_id', req.user.id)
      .neq('status', 'done')
      .limit(10);

    const { data: user } = await supabase
      .from('users')
      .select('name, role_title')
      .eq('id', req.user.id)
      .single();

    if (!events?.length) {
      return res.json({ proposals: [], message: 'No events to analyze this week.' });
    }

    // Build calendar summary for AI
    const byDay = {};
    events.forEach(ev => {
      const d = ev.start_time.slice(0, 10);
      if (!byDay[d]) byDay[d] = [];
      byDay[d].push(ev);
    });

    const calSummary = Object.entries(byDay).map(([date, evs]) => {
      const nonAllDay = evs.filter(e => !e.is_all_day);
      return `${date}: ${nonAllDay.length} meetings — ${nonAllDay.map(e =>
        `[${e.start_time.slice(11,16)} ${e.title}]`).join(', ')}`;
    }).join('\n');

    const actionSummary = (actions || []).map(a =>
      `- ${a.title} (due: ${a.due_date || 'no date'})`).join('\n');

    // Ask Claude to generate structured action proposals
    const prompt = `You are an agentic executive assistant for ${user?.name || 'a CEO'}.
Analyze this calendar and return ONLY a JSON array of action proposals. No other text.

CALENDAR THIS WEEK:
${calSummary}

OPEN ACTIONS:
${actionSummary || 'None'}

Return a JSON array where each item has:
{
  "id": "unique_string",
  "type": "reschedule" | "block_focus" | "add_action" | "cancel_meeting" | "send_reminder" | "protect_time",
  "title": "short action title",
  "description": "what this does and why",
  "risk": "low" | "medium" | "high",
  "auto_execute": true/false (true only if risk=low and non-destructive),
  "data": {
    "event_id": "google event id if applicable",
    "event_title": "event title",
    "from_time": "ISO string if reschedule",
    "to_time": "ISO string if reschedule",
    "duration_minutes": number if block_focus,
    "suggested_time": "ISO string if block_focus",
    "action_title": "string if add_action",
    "due_date": "YYYY-MM-DD if add_action"
  }
}

Generate 4-8 proposals. Prioritize: fix overloaded days, add missing focus blocks, flag late meetings, protect personal time after 6pm, add prep reminders for important meetings.`;

    const response = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': process.env.ANTHROPIC_API_KEY,
        'anthropic-version': '2023-06-01'
      },
      body: JSON.stringify({
        model: 'claude-sonnet-4-20250514',
        max_tokens: 2000,
        messages: [{ role: 'user', content: prompt }]
      })
    });

    const aiData = await response.json();
    let rawText = aiData.content?.[0]?.text || '[]';

    // Clean JSON
    rawText = rawText.replace(/```json|```/g, '').trim();
    let proposals = [];
    try { proposals = JSON.parse(rawText); } catch { proposals = []; }

    // SUGGEST-ONLY mode — always set auto_execute to false
    // User must approve every single action regardless of risk level
    proposals = proposals.map(p => ({
      ...p,
      auto_execute: false,  // always false — nothing runs without approval
      risk_label: p.risk === 'low' ? 'Low risk' : p.risk === 'medium' ? 'Medium risk' : 'Review carefully',
      status: 'pending'
    }));

    // Save proposals to DB for tracking
    await supabase.from('agent_proposals').upsert(
      proposals.map(p => ({
        user_id: req.user.id,
        proposal_id: p.id,
        type: p.type,
        title: p.title,
        description: p.description,
        risk: p.risk,
        data: p.data,
        status: 'pending',
        created_at: new Date().toISOString()
      })),
      { onConflict: 'user_id,proposal_id' }
    ).catch(() => {}); // table may not exist yet — non-fatal

    res.json({ proposals, analyzed_events: events.length });
  } catch (err) {
    console.error('[AGENT] Analyze error:', err.message);
    res.status(500).json({ error: 'Agent analysis failed: ' + err.message });
  }
});


// Execute an approved agent proposal
app.post('/api/agent/execute', requireAuth, async (req, res) => {
  const { proposal } = req.body;
  if (!proposal) return res.status(400).json({ error: 'proposal required' });

  const results = [];

  try {
    switch (proposal.type) {

      case 'reschedule': {
        // Move a Google Calendar event to a new time
        if (!proposal.data?.event_id || !proposal.data?.to_time) {
          results.push({ success: false, message: 'Missing event_id or to_time' });
          break;
        }
        try {
          const authClient = await getAuthClient(req.user.id);
          const calendar   = google.calendar({ version: 'v3', auth: authClient });
          const { data: existing } = await calendar.events.get({
            calendarId: 'primary', eventId: proposal.data.event_id
          });
          const duration = existing.end
            ? new Date(existing.end.dateTime) - new Date(existing.start.dateTime)
            : 3600000;
          const newStart = new Date(proposal.data.to_time);
          const newEnd   = new Date(newStart.getTime() + duration);
          await calendar.events.patch({
            calendarId: 'primary', eventId: proposal.data.event_id,
            resource: {
              start: { dateTime: newStart.toISOString(), timeZone: existing.start.timeZone || 'UTC' },
              end:   { dateTime: newEnd.toISOString(),   timeZone: existing.end?.timeZone   || 'UTC' }
            }
          });
          // Update Supabase cache
          await supabase.from('calendar_events')
            .update({ start_time: newStart.toISOString(), end_time: newEnd.toISOString(), updated_at: new Date().toISOString() })
            .eq('user_id', req.user.id).eq('google_event_id', proposal.data.event_id);
          results.push({ success: true, message: `Moved "${proposal.data.event_title}" to ${newStart.toLocaleString()}` });
        } catch (e) {
          // Fallback: create an action item to reschedule manually
          await supabase.from('action_items').insert({
            user_id: req.user.id,
            title: `Reschedule: ${proposal.data.event_title}`,
            due_date: new Date().toISOString().slice(0, 10),
            status: 'pending'
          });
          results.push({ success: true, message: `Added action item to reschedule "${proposal.data.event_title}" (calendar write requires re-authorization)` });
        }
        break;
      }

      case 'block_focus': {
        // Create a focus block event in Google Calendar
        try {
          const authClient = await getAuthClient(req.user.id);
          const calendar   = google.calendar({ version: 'v3', auth: authClient });
          const start = new Date(proposal.data.suggested_time || new Date());
          const end   = new Date(start.getTime() + (proposal.data.duration_minutes || 90) * 60000);
          await calendar.events.insert({
            calendarId: 'primary',
            resource: {
              summary: '🎯 Focus Block — ExecDesk',
              description: 'Protected deep work time. Auto-created by ExecDesk AI.',
              start: { dateTime: start.toISOString() },
              end:   { dateTime: end.toISOString() },
              colorId: '9' // Blueberry
            }
          });
          results.push({ success: true, message: `Focus block created: ${start.toLocaleTimeString()} – ${end.toLocaleTimeString()}` });
        } catch (e) {
          // Store locally if calendar write fails
          await supabase.from('action_items').insert({
            user_id: req.user.id,
            title: `Block focus time: ${proposal.data.duration_minutes || 90} min`,
            due_date: new Date().toISOString().slice(0, 10),
            status: 'pending'
          });
          results.push({ success: true, message: 'Focus block saved as action item (re-authorize calendar for auto-creation)' });
        }
        break;
      }

      case 'add_action': {
        const { error } = await supabase.from('action_items').insert({
          user_id: req.user.id,
          title: proposal.data.action_title || proposal.title,
          due_date: proposal.data.due_date || null,
          status: 'pending'
        });
        if (error) throw error;
        results.push({ success: true, message: `Action item added: "${proposal.data.action_title}"` });
        break;
      }

      case 'protect_time': {
        // Add a "Personal Time" block
        try {
          const authClient = await getAuthClient(req.user.id);
          const calendar   = google.calendar({ version: 'v3', auth: authClient });
          const start = new Date(proposal.data.suggested_time || new Date());
          const end   = new Date(proposal.data.from_time ? new Date(proposal.data.from_time) : start.getTime() + 7200000);
          await calendar.events.insert({
            calendarId: 'primary',
            resource: {
              summary: '🏠 Personal Time — Protected',
              description: 'Protected personal time. Auto-created by ExecDesk AI.',
              start: { dateTime: start.toISOString() },
              end:   { dateTime: end.toISOString() },
              colorId: '4' // Sage
            }
          });
          results.push({ success: true, message: 'Personal time block added to your calendar' });
        } catch (e) {
          results.push({ success: false, message: 'Could not write to calendar. Re-authorize with calendar.events scope.' });
        }
        break;
      }

      default:
        results.push({ success: true, message: `Action "${proposal.type}" noted. No calendar change required.` });
    }

    // Mark proposal as executed
    await supabase.from('agent_proposals')
      .update({ status: 'executed', executed_at: new Date().toISOString() })
      .eq('user_id', req.user.id)
      .eq('proposal_id', proposal.id)
      .catch(() => {});

    res.json({ results, executed: true });

  } catch (err) {
    console.error('[AGENT] Execute error:', err.message);
    res.status(500).json({ error: 'Execution failed: ' + err.message });
  }
});


// Dismiss a proposal
app.post('/api/agent/dismiss', requireAuth, async (req, res) => {
  const { proposal_id } = req.body;
  await supabase.from('agent_proposals')
    .update({ status: 'dismissed' })
    .eq('user_id', req.user.id)
    .eq('proposal_id', proposal_id)
    .catch(() => {});
  res.json({ success: true });
});


// ═══════════════════════════════════════════════════════════════════════════
// FEATURE 2 — MICROSOFT 365 / OUTLOOK CALENDAR SYNC
// ═══════════════════════════════════════════════════════════════════════════

// Microsoft OAuth URL
app.get('/auth/microsoft/url', (req, res) => {
  const clientId    = process.env.MICROSOFT_CLIENT_ID;
  const redirectUri = encodeURIComponent(process.env.MICROSOFT_REDIRECT_URI || '');
  const scope       = encodeURIComponent('Calendars.ReadWrite User.Read offline_access');
  const url = `https://login.microsoftonline.com/common/oauth2/v2.0/authorize?client_id=${clientId}&response_type=code&redirect_uri=${redirectUri}&scope=${scope}&prompt=consent`;
  res.json({ url });
});


// Microsoft OAuth callback
app.get('/auth/microsoft/callback', async (req, res) => {
  const APP_URL = process.env.APP_URL || 'http://localhost';
  const { code, error } = req.query;

  if (error) return res.redirect(`${APP_URL}?error=${encodeURIComponent(error)}`);
  if (!code)  return res.redirect(`${APP_URL}?error=no_code_microsoft`);

  try {
    // Exchange code for tokens
    const tokenRes = await fetch('https://login.microsoftonline.com/common/oauth2/v2.0/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        client_id:     process.env.MICROSOFT_CLIENT_ID,
        client_secret: process.env.MICROSOFT_CLIENT_SECRET,
        code,
        redirect_uri:  process.env.MICROSOFT_REDIRECT_URI,
        grant_type:    'authorization_code'
      })
    });

    const tokens = await tokenRes.json();
    if (tokens.error) throw new Error(tokens.error_description || tokens.error);

    // Get Microsoft user profile
    const profileRes = await fetch('https://graph.microsoft.com/v1.0/me', {
      headers: { Authorization: `Bearer ${tokens.access_token}` }
    });
    const profile = await profileRes.json();

    // Find existing Supabase user by email
    const { data: existingUser } = await supabase
      .from('users')
      .select('id')
      .eq('email', profile.mail || profile.userPrincipalName)
      .single();

    const userId = existingUser?.id;
    if (!userId) {
      return res.redirect(`${APP_URL}?error=microsoft_user_not_found&email=${encodeURIComponent(profile.mail)}`);
    }

    // Store Microsoft tokens
    await supabase.from('users').update({
      microsoft_access_token:  tokens.access_token,
      microsoft_refresh_token: tokens.refresh_token,
      microsoft_token_expiry:  Date.now() + (tokens.expires_in * 1000),
      updated_at: new Date().toISOString()
    }).eq('id', userId);

    // Kick off Outlook sync
    syncOutlookForUser(userId, tokens.access_token).catch(console.error);

    res.redirect(`${APP_URL}?outlook_connected=true`);

  } catch (err) {
    console.error('[MICROSOFT] OAuth error:', err.message);
    res.redirect(`${APP_URL}?error=${encodeURIComponent('Microsoft auth failed: ' + err.message)}`);
  }
});


// Sync Outlook calendar events to Supabase
async function syncOutlookForUser(userId, accessToken) {
  // Refresh token if needed
  let token = accessToken;
  if (!token) {
    const { data: user } = await supabase
      .from('users')
      .select('microsoft_access_token, microsoft_refresh_token, microsoft_token_expiry')
      .eq('id', userId)
      .single();

    if (!user?.microsoft_access_token) {
      throw new Error('No Microsoft tokens. Please connect Outlook.');
    }

    // Refresh if expired
    if (user.microsoft_token_expiry && Date.now() > user.microsoft_token_expiry - 60000) {
      const refreshRes = await fetch('https://login.microsoftonline.com/common/oauth2/v2.0/token', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          client_id:     process.env.MICROSOFT_CLIENT_ID,
          client_secret: process.env.MICROSOFT_CLIENT_SECRET,
          refresh_token: user.microsoft_refresh_token,
          grant_type:    'refresh_token'
        })
      });
      const refreshed = await refreshRes.json();
      if (!refreshed.error) {
        token = refreshed.access_token;
        await supabase.from('users').update({
          microsoft_access_token: refreshed.access_token,
          microsoft_token_expiry: Date.now() + (refreshed.expires_in * 1000)
        }).eq('id', userId);
      } else {
        token = user.microsoft_access_token;
      }
    } else {
      token = user.microsoft_access_token;
    }
  }

  const now = new Date();
  const end = new Date(now.getTime() + 14 * 86400000);

  const eventsRes = await fetch(
    `https://graph.microsoft.com/v1.0/me/calendarView?startDateTime=${now.toISOString()}&endDateTime=${end.toISOString()}&$top=200&$orderby=start/dateTime`,
    { headers: { Authorization: `Bearer ${token}`, Prefer: 'outlook.timezone="UTC"' } }
  );
  const data = await eventsRes.json();

  const travelKeywords = ['flight','hotel','travel','airport','train','airbnb','check-in','fly','depart','arrive'];

  const events = (data.value || []).map(ev => {
    const title = ev.subject || '(No title)';
    const desc  = ev.body?.content || '';
    const isTravel  = travelKeywords.some(k => (title + desc).toLowerCase().includes(k));
    const isVirtual = !!(ev.isOnlineMeeting || ev.onlineMeeting);
    const attendees = (ev.attendees || []).map(a => ({
      name:  a.emailAddress?.name  || a.emailAddress?.address,
      email: a.emailAddress?.address
    }));

    return {
      user_id:         userId,
      google_event_id: 'ms_' + ev.id, // prefix to distinguish from Google
      title,
      description:     ev.body?.content?.slice(0, 500) || null,
      start_time:      ev.start?.dateTime ? new Date(ev.start.dateTime + 'Z').toISOString() : ev.start?.dateTime,
      end_time:        ev.end?.dateTime   ? new Date(ev.end.dateTime   + 'Z').toISOString() : ev.end?.dateTime,
      location:        ev.location?.displayName || null,
      attendees,
      meeting_link:    ev.onlineMeeting?.joinUrl || null,
      is_all_day:      ev.isAllDay || false,
      is_travel:       isTravel,
      is_virtual:      isVirtual,
      status:          ev.isCancelled ? 'cancelled' : 'confirmed',
      updated_at:      new Date().toISOString()
    };
  });

  if (events.length > 0) {
    await supabase.from('calendar_events')
      .upsert(events, { onConflict: 'user_id,google_event_id' });
  }

  console.log(`[OUTLOOK] Synced ${events.length} events for user ${userId}`);
  return events;
}


// Outlook sync endpoint
app.post('/api/calendar/sync-outlook', requireAuth, async (req, res) => {
  try {
    const events = await syncOutlookForUser(req.user.id);
    res.json({ success: true, synced: events.length, source: 'outlook' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Check Outlook connection status
app.get('/api/calendar/outlook-status', requireAuth, async (req, res) => {
  const { data } = await supabase
    .from('users')
    .select('microsoft_access_token, microsoft_token_expiry')
    .eq('id', req.user.id)
    .single();

  res.json({
    connected: !!data?.microsoft_access_token,
    expires_at: data?.microsoft_token_expiry || null
  });
});


// ═══════════════════════════════════════════════════════════════════════════
// FEATURE 3 — MEETING TRANSCRIPTION + AUTO ACTION EXTRACTION
// Accepts transcript text, returns AI summary + structured action items
// ═══════════════════════════════════════════════════════════════════════════

app.post('/api/transcription/extract', requireAuth, async (req, res) => {
  const { transcript, meeting_title, meeting_date } = req.body;
  if (!transcript || transcript.trim().length < 20) {
    return res.status(400).json({ error: 'Transcript must be at least 20 characters' });
  }

  const prompt = `You are an AI chief of staff extracting key information from a meeting transcript.

Meeting: "${meeting_title || 'Meeting'}"
Date: ${meeting_date || new Date().toLocaleDateString()}

TRANSCRIPT:
${transcript.slice(0, 8000)}

Return ONLY valid JSON with this structure:
{
  "summary": "2-3 sentence summary of what was discussed and decided",
  "key_decisions": ["decision 1", "decision 2"],
  "action_items": [
    {
      "task": "specific action item",
      "owner": "person responsible (or 'Me' if unclear)",
      "due_date": "YYYY-MM-DD or null",
      "priority": "high|medium|low"
    }
  ],
  "follow_up_questions": ["question 1", "question 2"],
  "sentiment": "positive|neutral|tense|productive",
  "next_meeting_topics": ["topic 1", "topic 2"]
}`;

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
        max_tokens: 1500,
        messages: [{ role: 'user', content: prompt }]
      })
    });

    const data = await response.json();
    let raw = data.content?.[0]?.text || '{}';
    raw = raw.replace(/```json|```/g, '').trim();

    let result;
    try { result = JSON.parse(raw); }
    catch { result = { summary: raw, action_items: [], key_decisions: [] }; }

    // Auto-save action items to DB (ones owned by "Me")
    const myActions = (result.action_items || []).filter(a =>
      !a.owner || a.owner.toLowerCase() === 'me' || a.owner.toLowerCase().includes('ceo')
    );

    if (myActions.length > 0) {
      await supabase.from('action_items').insert(
        myActions.map(a => ({
          user_id:  req.user.id,
          title:    `[${meeting_title || 'Meeting'}] ${a.task}`,
          due_date: a.due_date || null,
          status:   'pending',
          priority: a.priority || 'medium'
        }))
      );
    }

    // Save transcript and result to DB
    await supabase.from('meeting_transcripts').insert({
      user_id:        req.user.id,
      meeting_title:  meeting_title || 'Meeting',
      meeting_date:   meeting_date || new Date().toISOString().slice(0, 10),
      transcript:     transcript.slice(0, 10000),
      ai_summary:     result.summary,
      action_items:   result.action_items,
      key_decisions:  result.key_decisions,
      created_at:     new Date().toISOString()
    }).catch(() => {}); // table may not exist yet

    res.json({
      ...result,
      auto_saved_actions: myActions.length,
      message: myActions.length > 0
        ? `${myActions.length} action item${myActions.length > 1 ? 's' : ''} auto-added to your list`
        : 'No personal action items detected'
    });

  } catch (err) {
    console.error('[TRANSCRIPTION] Error:', err.message);
    res.status(500).json({ error: 'Transcription extraction failed: ' + err.message });
  }
});


// Get past transcripts
app.get('/api/transcription/history', requireAuth, async (req, res) => {
  const { data, error } = await supabase
    .from('meeting_transcripts')
    .select('id, meeting_title, meeting_date, ai_summary, action_items, key_decisions, created_at')
    .eq('user_id', req.user.id)
    .order('created_at', { ascending: false })
    .limit(20);

  if (error) return res.status(500).json({ error: error.message });
  res.json({ transcripts: data || [] });
});


// ═══════════════════════════════════════════════════════════════════════════
// FEATURE 4 — NATURAL LANGUAGE COMMAND PROCESSOR
// Interprets free-text commands and returns structured intents + executes them
// ═══════════════════════════════════════════════════════════════════════════

app.post('/api/nlp/command', requireAuth, async (req, res) => {
  const { command } = req.body;
  if (!command?.trim()) return res.status(400).json({ error: 'command required' });

  // Get context for the AI
  const now = new Date();
  const week = new Date(now.getTime() + 7 * 86400000);
  const [eventsRes, actionsRes, goalsRes] = await Promise.all([
    supabase.from('calendar_events').select('title, start_time, end_time, google_event_id')
      .eq('user_id', req.user.id)
      .gte('start_time', now.toISOString())
      .lte('start_time', week.toISOString())
      .order('start_time')
      .limit(30),
    supabase.from('action_items').select('id, title, due_date, status')
      .eq('user_id', req.user.id).neq('status', 'done').limit(10),
    supabase.from('goals').select('id, title, progress_pct').eq('user_id', req.user.id).limit(5)
  ]);

  const calCtx = (eventsRes.data || []).map(e =>
    `${e.start_time.slice(0,16).replace('T',' ')} — ${e.title} [id:${e.google_event_id}]`
  ).join('\n');

  const today = now.toISOString().slice(0, 10);
  const prompt = `You are an AI command interpreter for an executive assistant app.
Today is ${now.toLocaleDateString('en-US', { weekday:'long', year:'numeric', month:'long', day:'numeric' })}.

USER'S UPCOMING CALENDAR:
${calCtx || 'No upcoming events'}

USER'S OPEN ACTIONS:
${(actionsRes.data || []).map(a => `[${a.id}] ${a.title} (due: ${a.due_date || 'none'})`).join('\n') || 'None'}

USER COMMAND: "${command}"

Interpret the command and return ONLY valid JSON:
{
  "intent": "add_action | complete_action | search_calendar | block_focus | reschedule | check_schedule | update_goal | log_energy | ask_advisor | unknown",
  "confidence": 0.0-1.0,
  "response": "confirmation message to show the user (friendly, concise)",
  "action": {
    "type": "same as intent",
    "title": "if add_action",
    "due_date": "YYYY-MM-DD if specified, else null",
    "action_id": "if completing an existing action",
    "event_id": "google event id if calendar action",
    "query": "if search_calendar",
    "duration_minutes": "if block_focus",
    "energy_level": 1-5 if log_energy,
    "goal_progress": 0-100 if update_goal,
    "message": "if ask_advisor — the message to send"
  }
}`;

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
        max_tokens: 500,
        messages: [{ role: 'user', content: prompt }]
      })
    });

    const data = await response.json();
    let raw = data.content?.[0]?.text || '{}';
    raw = raw.replace(/```json|```/g, '').trim();

    let intent;
    try { intent = JSON.parse(raw); }
    catch { intent = { intent: 'unknown', confidence: 0.5, response: raw, action: {} }; }

    // Auto-execute safe intents
    let executed = false;
    let executionResult = null;

    if (intent.confidence >= 0.75) {
      switch (intent.intent) {
        case 'add_action': {
          const { data: newAction } = await supabase.from('action_items').insert({
            user_id:  req.user.id,
            title:    intent.action?.title || command,
            due_date: intent.action?.due_date || null,
            status:   'pending'
          }).select().single();
          executed = true;
          executionResult = { action_id: newAction?.id };
          break;
        }
        case 'complete_action': {
          if (intent.action?.action_id) {
            await supabase.from('action_items')
              .update({ status: 'done', updated_at: new Date().toISOString() })
              .eq('id', intent.action.action_id)
              .eq('user_id', req.user.id);
            executed = true;
          }
          break;
        }
        case 'log_energy': {
          if (intent.action?.energy_level) {
            // This is stored client-side in localStorage — return the value to execute
            executed = true;
            executionResult = { energy_level: intent.action.energy_level, date: today };
          }
          break;
        }
      }
    }

    res.json({
      ...intent,
      executed,
      execution_result: executionResult,
      original_command: command
    });

  } catch (err) {
    console.error('[NLP] Error:', err.message);
    res.status(500).json({ error: 'Command processing failed: ' + err.message });
  }
});


// ═══════════════════════════════════════════════════════════════════════════
// SUPABASE SCHEMA ADDITIONS
// Run these in Supabase SQL Editor to support new features
// ═══════════════════════════════════════════════════════════════════════════

/*
-- Agent proposals table
CREATE TABLE IF NOT EXISTS public.agent_proposals (
  id            uuid default uuid_generate_v4() primary key,
  user_id       uuid not null references public.users(id) on delete cascade,
  proposal_id   text not null,
  type          text not null,
  title         text not null,
  description   text,
  risk          text default 'medium',
  data          jsonb default '{}',
  status        text default 'pending',
  executed_at   timestamptz,
  created_at    timestamptz default now(),
  unique(user_id, proposal_id)
);
ALTER TABLE public.agent_proposals DISABLE ROW LEVEL SECURITY;

-- Meeting transcripts table
CREATE TABLE IF NOT EXISTS public.meeting_transcripts (
  id             uuid default uuid_generate_v4() primary key,
  user_id        uuid not null references public.users(id) on delete cascade,
  meeting_title  text,
  meeting_date   date,
  transcript     text,
  ai_summary     text,
  action_items   jsonb default '[]',
  key_decisions  jsonb default '[]',
  created_at     timestamptz default now()
);
ALTER TABLE public.meeting_transcripts DISABLE ROW LEVEL SECURITY;

-- Microsoft tokens in users table
ALTER TABLE public.users ADD COLUMN IF NOT EXISTS microsoft_access_token  text;
ALTER TABLE public.users ADD COLUMN IF NOT EXISTS microsoft_refresh_token text;
ALTER TABLE public.users ADD COLUMN IF NOT EXISTS microsoft_token_expiry  bigint;
*/


// ═══════════════════════════════════════════════════════════════════════════
// EMAIL + PASSWORD AUTH ROUTES
// Add these to server.js alongside the existing OAuth routes
// Supabase handles password hashing and email confirmation automatically
// ═══════════════════════════════════════════════════════════════════════════

// Sign up with email + password
app.post('/auth/email/signup', async (req, res) => {
  const { name, email, password } = req.body;
  if (!email || !password || !name)
    return res.status(400).json({ error: 'Name, email and password are required.' });
  if (password.length < 8)
    return res.status(400).json({ error: 'Password must be at least 8 characters.' });

  try {
    const { data, error } = await supabase.auth.signUp({
      email, password,
      options: { data: { name } }
    });
    if (error) {
      // Surface friendly messages for common Supabase errors
      if (error.message.includes('already registered'))
        return res.status(400).json({ error: 'This email is already registered. Please sign in instead.' });
      return res.status(400).json({ error: error.message });
    }

    // If email confirmation is disabled in Supabase (Settings → Auth → Email),
    // the session is returned immediately and we can sign them straight in.
    if (data.session) {
      // Upsert user profile
      await supabase.from('users').upsert({
        id: data.user.id, email, name,
        updated_at: new Date().toISOString()
      }, { onConflict: 'id' }).catch(() => {});

      return res.json({
        token:   data.session.access_token,
        refresh: data.session.refresh_token,
        user:    { id: data.user.id, email, name }
      });
    }

    // Email confirmation is ON — tell the frontend to wait
    res.json({ message: 'Please check your email to confirm your account.' });
  } catch (err) {
    res.status(500).json({ error: 'Sign up failed: ' + err.message });
  }
});


// Sign in with email + password
app.post('/auth/email/signin', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password)
    return res.status(400).json({ error: 'Email and password are required.' });

  try {
    const { data, error } = await supabase.auth.signInWithPassword({ email, password });
    if (error) {
      if (error.message.includes('Invalid login'))
        return res.status(401).json({ error: 'Incorrect email or password. Please try again.' });
      if (error.message.includes('Email not confirmed'))
        return res.status(401).json({ error: 'Please confirm your email address first. Check your inbox.' });
      return res.status(401).json({ error: error.message });
    }

    // Ensure user row exists in our users table
    const { data: profile } = await supabase
      .from('users').select('name, role_title, subscription_tier')
      .eq('id', data.user.id).single();

    if (!profile) {
      await supabase.from('users').upsert({
        id: data.user.id, email,
        name: data.user.user_metadata?.name || email.split('@')[0],
        updated_at: new Date().toISOString()
      }, { onConflict: 'id' }).catch(() => {});
    }

    res.json({
      token:   data.session.access_token,
      refresh: data.session.refresh_token,
      user: {
        id:    data.user.id,
        email: data.user.email,
        name:  profile?.name || data.user.user_metadata?.name || email.split('@')[0],
        role_title:        profile?.role_title || null,
        subscription_tier: profile?.subscription_tier || 'free'
      }
    });
  } catch (err) {
    res.status(500).json({ error: 'Sign in failed: ' + err.message });
  }
});


// Forgot password — sends reset email via Supabase
app.post('/auth/email/forgot', async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: 'Email is required.' });

  try {
    await supabase.auth.resetPasswordForEmail(email, {
      redirectTo: `${process.env.APP_URL}/reset-password`
    });
    // Always return success — don't reveal whether email exists (security)
    res.json({ message: 'If that email exists, a reset link has been sent.' });
  } catch (err) {
    res.json({ message: 'If that email exists, a reset link has been sent.' });
  }
});


// Delete account — removes all user data
app.delete('/api/account', requireAuth, async (req, res) => {
  const userId = req.user.id;
  try {
    // Delete all user data in order (foreign key safe)
    await supabase.from('ai_conversations').delete().eq('user_id', userId);
    await supabase.from('action_items').delete().eq('user_id', userId);
    await supabase.from('goals').delete().eq('user_id', userId);
    await supabase.from('calendar_events').delete().eq('user_id', userId);
    await supabase.from('agent_proposals').delete().eq('user_id', userId).catch(() => {});
    await supabase.from('meeting_transcripts').delete().eq('user_id', userId).catch(() => {});
    await supabase.from('users').delete().eq('id', userId);
    // Delete Supabase Auth user (requires service role key)
    await supabase.auth.admin.deleteUser(userId);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Account deletion failed: ' + err.message });
  }
});

// ── SETUP NOTE ────────────────────────────────────────────────────────────────
// To disable email confirmation (simpler for launch):
// Supabase Dashboard → Authentication → Settings → Email Auth
// → Disable "Enable email confirmations"
// Users will be signed in immediately after registering.

// ── START ─────────────────────────────────────────────────────────────────────
app.listen(PORT, () => console.log(`ExecDesk backend running on port ${PORT}`));
