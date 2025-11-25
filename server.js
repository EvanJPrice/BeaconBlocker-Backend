// FILE: server.js
// VERSION: v6.3 (Shorts Circuit + Nuanced Prompt + Silent System Rules)

// --- Imports ---
console.log("DEBUG: Starting server script...");
require('dotenv').config();
console.log("DEBUG: dotenv loaded.");
const { GoogleGenerativeAI } = require('@google/generative-ai');
console.log("DEBUG: generative-ai loaded.");
const express = require('express');
console.log("DEBUG: express loaded.");
const cors = require('cors');
console.log("DEBUG: cors loaded.");
const { createClient } = require('@supabase/supabase-js');
console.log("DEBUG: supabase-js loaded.");

// --- Setup ---
console.log("DEBUG: Reading env vars...");
const supabaseUrl = process.env.SUPABASE_URL;
const supabaseKey = process.env.SUPABASE_ANON_KEY;
const geminiKey = process.env.GOOGLE_API_KEY;

if (!supabaseUrl || !supabaseKey || !geminiKey) {
    console.error("❌ ERROR: Missing .env variables!");
    process.exit(1);
}

const genAI = new GoogleGenerativeAI(geminiKey);
console.log("DEBUG: Initializing Supabase...");
const supabase = createClient(supabaseUrl, supabaseKey);
console.log("DEBUG: Initializing Gemini...");
console.log("DEBUG: Connected to Supabase URL:", supabaseUrl); // Verify this matches Vercel!
const model = genAI.getGenerativeModel({
    model: "gemini-flash-latest",
    generationConfig: { temperature: 0.0 }
});
const app = express();
const port = process.env.PORT || 3000;
app.use(cors());
app.use(express.json());

// --- Middleware: Verify Supabase JWT ---
async function verifyToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) return res.status(401).json({ error: 'Missing Authorization Token' });

    const { data: { user }, error } = await supabase.auth.getUser(token);

    if (error || !user) {
        return res.status(403).json({ error: 'Invalid or Expired Token' });
    }

    req.user = user; // Attach user to request
    next();
}

// --- API Endpoint: Login ---
app.post('/login', async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Missing email or password' });

    const { data, error } = await supabase.auth.signInWithPassword({
        email: email,
        password: password,
    });

    if (error) {
        console.error("DEBUG: Login Failed for", email);
        console.error("DEBUG: Supabase Error:", error);
        return res.status(401).json({ error: error.message });
    }

    res.json({
        session: data.session,
        user: data.user
    });
});

// --- 1. INFRASTRUCTURE ALLOW LIST ---
const SYSTEM_ALLOWED_DOMAINS = [
    'onrender.com', 'supabase.co', 'accounts.google.com',
    'beaconblocker.com', 'vercel.app'
];

function getDomainFromUrl(urlString) {
    if (!urlString) return null;
    try {
        let fullUrl = urlString.trim();
        if (!fullUrl.startsWith('http://') && !fullUrl.startsWith('https://')) {
            fullUrl = 'http://' + fullUrl;
        }
        const url = new URL(fullUrl);
        const parts = url.hostname.split('.');
        if (parts.length >= 2) {
            if (parts.length > 2 && parts[parts.length - 2].length <= 3 && parts[parts.length - 1].length <= 3) {
                return parts.slice(-3).join('.').toLowerCase();
            }
            return parts.slice(-2).join('.').toLowerCase();
        }
        return url.hostname.toLowerCase();
    } catch (e) { console.error("Error extracting domain:", e); return null; }
}

// --- Helper: Log Blocking Event (FIXED SUPPRESSION) ---
async function logBlockingEvent(logData) {
    const { userId, url, decision, reason, pageTitle } = logData;
    if (!userId) return;

    // --- THE FIX IS HERE ---
    // Explicitly skip Search and Navigation logs so they don't clutter the dashboard.
    if (reason === 'System Rule (Infra)' ||
        reason === 'Search Allowed' ||
        reason === 'YouTube Navigation') {
        return;
    }

    try {
        const domain = getDomainFromUrl(url);
        const { error } = await supabase.from('blocking_log').insert({
            user_id: userId,
            url: url || 'Unknown URL',
            domain: domain || 'Unknown Domain',
            decision: decision,
            reason: reason,
            page_title: pageTitle || ''
        });
        if (error) console.error("Error logging event:", error.message);
    } catch (err) { console.error("Logging exception:", err.message); }
}

async function getUserRuleData(userId) {
    if (!userId) return null;
    const { data, error } = await supabase
        .from('rules')
        .select('user_id, prompt, blocked_categories, allow_list, block_list, last_seen')
        .eq('user_id', userId)
        .single();

    if (error || !data) return null;
    data.allow_list = data.allow_list || [];
    data.block_list = data.block_list || [];
    data.blocked_categories = data.blocked_categories || {};
    return data;
}

// --- AI Decision Function ---
async function getAIDecision(pageData, ruleData) {
    const { title, description, h1, url, searchQuery, keywords, bodyText } = pageData;
    const { prompt: userMainPrompt, blocked_categories } = ruleData;

    console.log(`AI Input: Title='${title}'`);

    // 1. Auto-Allow Exact Matches
    if (searchQuery && title) {
        const cleanSearch = searchQuery.toLowerCase().trim();
        const cleanTitle = title.toLowerCase().trim();
        if (cleanTitle.includes(cleanSearch) || cleanSearch.includes(cleanTitle)) {
            console.log(`Auto-Allow: Search '${cleanSearch}' matches title.`);
            return 'ALLOW';
        }
    }

    let finalPrompt = userMainPrompt || "No prompt provided.";
    const BLOCKED_CATEGORY_LABELS = {
        'social': 'Social Media', 'news': 'News & Politics',
        'entertainment': 'Entertainment', 'games': 'Games',
        'shopping': 'Online Shopping', 'mature': 'Mature Content'
    };
    const selectedCategoryLabels = Object.entries(blocked_categories || {})
        .filter(([, value]) => value === true)
        .map(([key]) => BLOCKED_CATEGORY_LABELS[key] || key);

    if (selectedCategoryLabels.length > 0) {
        finalPrompt += `\n\n**Explicitly Blocked Categories:**\n- ${selectedCategoryLabels.join('\n- ')}`;
    }

    finalPrompt += `\n\nAnalyze this webpage:
    - URL: "${url}"
    - Title: "${title || 'N/A'}"
    - Description: "${description || 'N/A'}"
    - Keywords: "${keywords || 'N/A'}" 
    - Body Snippet: "${bodyText || 'N/A'}" 
    - Search Query (Context): "${searchQuery || 'N/A'}"

    My user's rule details are above.
    **CRITICAL INSTRUCTIONS (Priority Order):**
    1. **User's Main Prompt:** Highest priority. If they explicitly allow a topic, ALLOW it.
    2. **Search Match:** If the Search Query matches the video topic, assume productive intent -> ALLOW.
    3. **Category Definitions (Strict):**
       - **"Games":** Refers ONLY to **interactive gameplay**. Not videos about games.
       - **"Entertainment":** Refers to **passive watching** (Netflix, Viral Clips, Gameplay Videos).
       - **"Shopping":** Refers ONLY to **transactional pages**. Not reviews.
    4. **General:** Respond with *only* ALLOW or BLOCK.
    `;

    try {
        const result = await model.generateContent(finalPrompt);
        const response = await result.response;
        let decision = response.text().trim().toUpperCase();
        if (decision.includes('BLOCK')) return 'BLOCK';
        if (decision.includes('ALLOW')) return 'ALLOW';
        return 'BLOCK';
    } catch (error) {
        console.error('AI Error:', error.message);
        return 'BLOCK';
    }
}

// --- API Endpoint: Check URL ---
app.post('/check-url', verifyToken, async (req, res) => {
    const pageData = req.body;
    const url = pageData?.url;
    const userId = req.user.id; // From middleware

    if (!url) return res.status(400).json({ error: 'Missing URL' });

    try {
        const ruleData = await getUserRuleData(userId);
        if (!ruleData) return res.status(404).json({ error: "User rules not found" });
        // userId is already set
        const { allow_list, block_list, blocked_categories } = ruleData;

        const urlObj = new URL(url);
        const hostname = urlObj.hostname.toLowerCase();
        const pathname = urlObj.pathname;
        const baseDomain = getDomainFromUrl(url);

        // 1. Infrastructure
        if (baseDomain && SYSTEM_ALLOWED_DOMAINS.some(d => baseDomain.endsWith(d))) {
            return res.json({ decision: 'ALLOW' });
        }

        // 2. Search Engines
        if ((hostname.includes('google.') || hostname.includes('bing.') || hostname.includes('duckduckgo.'))
            && (pathname === '/' || pathname.startsWith('/search'))) {
            // Silent Allow
            return res.json({ decision: 'ALLOW' });
        }

        // 3. YouTube Browsing
        if (hostname.endsWith('youtube.com')) {
            if (!pathname.startsWith('/watch') && !pathname.startsWith('/shorts')) {
                // Silent Allow
                return res.json({ decision: 'ALLOW' });
            }
        }

        // 4. User Lists
        if (baseDomain && allow_list.some(d => baseDomain === d || baseDomain.endsWith('.' + d))) {
            await logBlockingEvent({ userId, url, decision: 'ALLOW', reason: 'Matched Allow List', pageTitle: pageData?.title });
            return res.json({ decision: 'ALLOW' });
        }

        if (baseDomain && block_list.some(d => baseDomain === d || baseDomain.endsWith('.' + d))) {
            await logBlockingEvent({ userId, url, decision: 'BLOCK', reason: 'Matched Block List', pageTitle: pageData?.title });
            return res.json({ decision: 'BLOCK' });
        }

        // --- 4.5 SHORTS CIRCUIT (v8.1 - Uses "Shorts" category) ---
        if (pathname.startsWith('/shorts/') || pathname.startsWith('/reels/') || baseDomain.includes('tiktok')) {
            // Check the NEW "shorts" category from the dashboard
            const isShortsBlocked = blocked_categories['shorts'];
            const hasSearch = !!pageData.searchQuery;

            // --- Logic with Search "Carve-Out" ---

            // 1. Did the user search for this? (e.g., "how to fix sink shorts")
            if (hasSearch) {
                console.log("Shorts: Allowing due to Search Context. Proceeding to AI.");
                // Fall through to the AI Check (Step 5)
                // The AI will see the search context and (hopefully) allow it.

                // 2. Did the user block the "Shorts" category and NOT search?
            } else if (isShortsBlocked) {
                // This is doomscrolling. Block it.
                console.log("Shorts Circuit: Blocking (Category Toggled, No Search)");
                await logBlockingEvent({
                    userId,
                    url,
                    decision: 'BLOCK',
                    reason: 'Category: Short-Form',
                    pageTitle: pageData?.title || 'YouTube Short'
                });
                return res.json({ decision: 'BLOCK' });

                // 3. User has NOT blocked shorts and is NOT searching.
            } else {
                // Allow it silently without logging to prevent clutter.
                console.log("Shorts Circuit: Allowed (Category Unchecked)");
                return res.json({ decision: 'ALLOW' });
            }
        }

        // 5. AI Check
        console.log("Proceeding to AI Check...");
        const decision = await getAIDecision(pageData, ruleData);

        let logTitle = pageData?.title || "Unknown Page";
        if (pageData.searchQuery) logTitle += ` [Search: '${pageData.searchQuery}']`;

        await logBlockingEvent({ userId, url, decision, reason: 'AI Decision', pageTitle: logTitle });
        res.json({ decision: decision });

    } catch (err) {
        console.error("Server Error:", err.message);
        await logBlockingEvent({ userId, url, decision: 'BLOCK', reason: 'Server Error', pageTitle: pageData?.title });
        res.status(500).json({ error: "Internal Server Error" });
    }
});

// --- Heartbeat ---


// --- API Endpoint: Manual Log (for Shorts Session) ---
app.post('/log-event', verifyToken, async (req, res) => {
    // Get log data from the background script
    const { title, reason, decision } = req.body;
    const userId = req.user.id;

    try {
        // Use our existing helper to log the event
        await logBlockingEvent({
            userId: userId,
            url: 'https://www.youtube.com/shorts', // Use a generic URL
            decision: decision || 'ALLOW',
            reason: reason || 'Shorts Session',
            pageTitle: title
        });
        res.json({ success: true });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

app.listen(port, () => {
    console.log(`✅ SERVER IS LIVE on port ${port}`);
});
console.log(`DEBUG: Attempting to listen on port ${port}...`);