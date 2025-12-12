// FILE: server.js
// VERSION: v6.3 (Shorts Circuit + Nuanced Prompt + Silent System Rules)
console.log(`\n\n-- - 🚀 SERVER RESTARTED AT ${new Date().toLocaleTimeString()} ---\n\n`);
// --- 🕵️ DEBUG COUNTERS ---
let requestCount = 0; // Total traffic from browser
let aiCostCount = 0;  // Actual calls to Google (The "Billable" ones)

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
const supabaseServiceKey = process.env.SUPABASE_SERVICE_ROLE_KEY; // Try to get service role key
const geminiKey = process.env.GOOGLE_API_KEY;

if (!supabaseUrl || !supabaseKey || !geminiKey) {
    console.error("❌ ERROR: Missing .env variables!");
    process.exit(1);
}

const genAI = new GoogleGenerativeAI(geminiKey);
console.log("DEBUG: Initializing Supabase...");
const supabase = createClient(supabaseUrl, supabaseKey); // For Auth verification
// Use Service Role Key for DB writes if available, otherwise fallback (which might fail RLS)
const supabaseAdmin = supabaseServiceKey ? createClient(supabaseUrl, supabaseServiceKey) : supabase;

console.log("DEBUG: Initializing Gemini...");
console.log("DEBUG: Connected to Supabase URL:", supabaseUrl);
if (supabaseServiceKey) console.log("DEBUG: Service Role Key loaded for DB writes.");

const model = genAI.getGenerativeModel({
    model: "gemini-flash-latest",  // Using latest flash model (requires paid tier for sufficient quota)
    generationConfig: { temperature: 0.0 }
});
const app = express();

const port = process.env.PORT || 3000;
app.use(cors());
app.use(express.json());

// --- Debug Middleware ---
app.use((req, res, next) => {
    console.log(`DEBUG: Incoming Request: ${req.method} ${req.url}`);
    next();
});

// --- Global Cache Versioning ---
// This allows the server to force all extensions to clear their cache when rules change.
let globalCacheVersion = Date.now();

// --- Root Route for Verification ---
app.get('/', (req, res) => {
    res.send('✅ Beacon Blocker Backend is Running!');
});

// --- API Endpoint: Test Email (Debug) ---
app.get('/test-email', async (req, res) => {
    if (!process.env.EMAIL_USER || !process.env.EMAIL_PASS) {
        return res.status(400).json({ error: "Missing EMAIL_USER or EMAIL_PASS in .env" });
    }

    try {
        const emailPass = process.env.EMAIL_PASS.replace(/\s+/g, '');
        const transporter = nodemailer.createTransport({
            host: process.env.EMAIL_HOST || 'smtp.gmail.com',
            port: process.env.EMAIL_PORT || 587,
            secure: false,
            auth: {
                user: process.env.EMAIL_USER,
                pass: emailPass,
            },
        });

        await transporter.verify();
        await transporter.sendMail({
            from: process.env.EMAIL_USER,
            to: process.env.EMAIL_USER,
            subject: "Test Email from Beacon Blocker",
            text: "If you see this, your email configuration is working!"
        });

        res.json({ success: true, message: "Email configuration is valid and test email sent!" });
    } catch (error) {
        console.error("Email Test Failed:", error);
        res.status(500).json({
            error: "Email Test Failed",
            message: error.message,
            code: error.code,
            command: error.command,
            response: error.response,
            stack: error.stack
        });
    }
});

// --- API Endpoint: Increment Cache Version ---
// Call this when rules are updated
app.post('/update-rules-signal', verifyToken, (req, res) => {
    globalCacheVersion = Date.now();
    console.log(`Rules updated. New Cache Version: ${globalCacheVersion}`);
    res.json({ success: true, cacheVersion: globalCacheVersion });
});

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

// --- Helper: Log Blocking Event ---
async function logBlockingEvent(logData) {
    const { userId, url, decision, reason, pageTitle } = logData;
    if (!userId) return;

    // Skip only System Rules (Infra) to keep logs clean, but ALLOW Search/Nav logs now.
    if (reason === 'System Rule (Infra)') {
        return;
    }

    try {
        const domain = getDomainFromUrl(url);
        console.log(`DEBUG: Attempting to log event for user ${userId} - ${url}`);

        // Use supabaseAdmin to bypass RLS
        const { data, error } = await supabaseAdmin.from('blocking_log').insert({
            user_id: userId,
            url: url || 'Unknown URL',
            domain: domain || 'Unknown Domain',
            decision: decision,
            reason: reason,
            page_title: pageTitle || ''
        }).select();

        if (error) {
            console.error("❌ ERROR logging event:", error.message, error.details);
        } else {
            console.log("✅ Event logged successfully:", data);
        }
    } catch (err) { console.error("Logging exception:", err.message); }
}

async function getUserRuleData(userId) {
    if (!userId) return null;
    // console.log(`DEBUG: Fetching rules for user ${userId}`);

    // MUST use supabaseAdmin to bypass RLS, as the server has no user session
    const { data, error } = await supabaseAdmin
        .from('rules')
        .select('prompt, blocked_categories, allow_list, block_list, last_updated')
        .eq('user_id', userId)
        .limit(1);

    if (error) {
        console.error("DEBUG: Error fetching rules:", error.message);
        return null;
    }

    if (!data || data.length === 0) {
        // console.log("DEBUG: No rules found for user (New Account?)");
        return { prompt: '', blocked_categories: {}, allow_list: [], block_list: [] };
    }

    const ruleData = data[0];
    // DEBUG LOG: Prove that we have the time
    console.log(`DEBUG: Rule Time Fetch: ${ruleData.last_updated ? 'Success' : 'MISSING'}`)

    ruleData.allow_list = ruleData.allow_list || [];
    ruleData.block_list = ruleData.block_list || [];



    // Ensure blocked_categories is an object
    if (typeof ruleData.blocked_categories === 'string') {
        try {
            ruleData.blocked_categories = JSON.parse(ruleData.blocked_categories);
        } catch (e) {
            console.error("Error parsing blocked_categories:", e);
            ruleData.blocked_categories = {};
        }
    }
    ruleData.blocked_categories = ruleData.blocked_categories || {};

    return ruleData;
}

async function getAIDecision(pageData, ruleData) {
    const { title, url, localTime, bodyText, description, keywords, searchQuery } = pageData;
    const { prompt: userMainPrompt, blocked_categories, last_updated } = ruleData;

    // --- 1. DEFINE TIME CONTEXT ---
    let diffMinutes = 0;

    // Parse the user's local time for structured data (e.g., "Tuesday, 8:44 AM")
    // We'll also provide 24-hour format for easier AI parsing
    const now = new Date();
    const userHour24 = now.getHours(); // 0-23
    const userMinute = now.getMinutes();
    const userHour12 = userHour24 % 12 || 12;
    const ampm = userHour24 >= 12 ? 'PM' : 'AM';

    let timeContext = `**CURRENT USER TIME:** "${localTime || 'Unknown'}"
**CURRENT TIME (24h):** ${userHour24}:${String(userMinute).padStart(2, '0')}
**CURRENT TIME (12h):** ${userHour12}:${String(userMinute).padStart(2, '0')} ${ampm}
`;

    // --- 2. CALCULATE RULE AGE (for timer blocks) ---
    if (last_updated) {
        const lastUpdateDate = new Date(last_updated);
        const diffMs = now - lastUpdateDate;
        diffMinutes = Math.floor(diffMs / 60000);

        console.log(`⏱️ DEBUG: Rule is ${diffMinutes} minutes old.`);

        timeContext += `**RULE SET:** ${diffMinutes} minutes ago.
**TIMER BLOCK MATH:** If user sets a duration (e.g., "for 30 mins"):
    REMAINING = Duration - ${diffMinutes}
    If REMAINING > 0 → ACTIVE (include "(X mins left)" in reason)
    If REMAINING <= 0 → EXPIRED → ALLOW

**CLOCK BLOCK MATH:** If user sets an absolute time (e.g., "until 5pm" or "after 3pm"):
    Convert target to 24h format (5pm = 17:00, 9am = 9:00)
    Current time is ${userHour24}:${String(userMinute).padStart(2, '0')}
    "until 5pm" means BLOCK if current < 17:00, else ALLOW
    "after 6pm" means BLOCK if current >= 18:00, else ALLOW
`;
    } else {
        console.log("⚠️ DEBUG: No timestamp found. Assuming 0 minutes.");
        timeContext += `**RULE SET:** Just now (0 minutes ago).
`;
    }

    console.log(`AI Input: Title='${title}'`);

    // --- Auto-Allow Exact Matches ---
    if (searchQuery && title) {
        const cleanSearch = searchQuery.toLowerCase().trim();
        const cleanTitle = title.toLowerCase().trim();
        if (cleanTitle.includes(cleanSearch) || cleanSearch.includes(cleanTitle)) {
            console.log(`Auto-Allow: Search '${cleanSearch}' matches title.`);
            return { decision: 'ALLOW', reason: `Matches search: "${cleanSearch}"` };
        }
    }

    // --- Passive Mode Check (EARLY EXIT - Save API calls) ---
    const hasPrompt = userMainPrompt && userMainPrompt.trim().length > 0;
    const hasCategories = blocked_categories && Object.values(blocked_categories).some(v => v === true);

    if (!hasPrompt && !hasCategories) {
        return { decision: 'ALLOW', reason: `No rules set (Passive Mode)` };
    }

    // let finalPrompt = userMainPrompt || "No specific focus goal provided."; // REMOVED DUPLICATE
    const BLOCKED_CATEGORY_LABELS = {
        'social': 'Social Media', 'news': 'News & Politics',
        'entertainment': 'Movies & TV', 'games': 'Games',
        'shopping': 'Online Shopping', 'mature': 'Mature Content',
        'shorts': 'Short-Form Content', // Added in v8.1
        'streaming': 'Streaming Services', // Added in v8.2
        'sports': 'Sports', // Added in v8.3
        'finance': 'Finance', // Added in v8.3
        'travel': 'Travel & Real Estate', // Added in v8.3
        'forums': 'Forums' // Added in v8.3
    };
    const CATEGORY_DEFINITIONS = `
- Social Media: Facebook, Instagram, Twitter/X, LinkedIn, Snapchat, Pinterest, Tumblr.
- Shorts & Reels: TikTok, YouTube Shorts, Instagram Reels.
- News & Politics: CNN, Fox, BBC, NYT, Washington Post, The Guardian.
- Movies & TV: Premium Movies & TV Series (Netflix, Hulu, Disney+, HBO, Prime Video). NOT YouTube/Twitch.
- Streaming Services: User-Generated Content & Live Streams (YouTube, Twitch, Kick). NOT Netflix/Hulu.
- Gaming: Steam, Roblox, IGN, Kotaku, Discord (Gaming communities).
- Sports: ESPN, NBA, NFL, MLB, Live Sports, Sports News.
- Finance: Coinbase, Binance, Stocks, Trading, Financial News.
- Travel & Real Estate: Airbnb, Zillow, Booking, Redfin, Trulia, Expedia, Hotels.
- Forums: Reddit, Quora, StackOverflow, Hacker News.
- Shopping: Amazon, eBay, Shopify, Etsy, Walmart, Target.
- Mature Content: Adult sites, Gambling, Betting.
`;
    const selectedCategoryLabels = Object.entries(blocked_categories || {})
        .filter(([, value]) => value === true)
        .map(([key]) => BLOCKED_CATEGORY_LABELS[key] || key);

    const explicitBlockList = selectedCategoryLabels.join(', ');

    const finalPrompt = `
    You are a strict website blocking assistant.
    
    **USER'S MAIN PROMPT:** "${userMainPrompt || 'No specific prompt provided.'}"
    
    ${timeContext} 
    
    **EXPLICITLY BLOCKED CATEGORIES:** [${explicitBlockList}]
    (If a category is NOT listed here, it is ALLOWED unless the Main Prompt says otherwise).

    **WEBSITE CONTENT:**
    - URL: "${url}"
    - Title: "${title || 'N/A'}"
    - Description: "${description || 'N/A'}"
    - Keywords: "${keywords || 'N/A'}" 
    - Body Snippet: "${bodyText || 'N/A'}" 

    **OUTPUT FORMAT:**
    Respond with valid JSON ONLY. No markdown formatting.
    {
        "decision": "ALLOW" or "BLOCK",
        "reason": "A short, concise explanation (max 6 words). State only the rationale - DO NOT mention 'blocked', 'blocking', or 'allowed'. Examples: 'Social Media', 'News & Politics', 'Distraction from study goal', 'Matches study topic'."
    }

    **CRITICAL INSTRUCTIONS (Priority Order):**
    1. **Time Limits (HIGHEST PRIORITY):** 
       - **TIMER BLOCKS (duration):** "for 30 mins", "for 2 hours" → Use TIMER BLOCK MATH above. If REMAINING > 0, enforce rule. Include "(X mins left)" in reason. If expired → ALLOW with reason "Timer expired".
       - **CLOCK BLOCKS (absolute time):** "until 5pm", "after 9am", "before noon" → Use CLOCK BLOCK MATH above. Compare CURRENT TIME (24h) with target time.
         - "until 5pm" (17:00): If current < 17:00 → enforce rule with "(until 5pm)", else ALLOW with reason "Past 5:00 PM"
         - "after 6pm" (18:00): If current >= 18:00 → enforce rule, else ALLOW with reason "Before 6:00 PM"
         - "block until 9am": If current >= 9:00 → ALLOW with reason "Past 9:00 AM"
    2. **User's Main Prompt:** If they explicitly allow a topic, ALLOW it.
    3. **Platform Overrides Content (CRITICAL):**
       - If the URL belongs to a known platform, you MUST classify it under that platform's category, regardless of the specific content.
       - **YouTube/Twitch** = **Streaming Services** (NOT Entertainment, NOT Education).
       - **Netflix/Hulu** = **Entertainment** (NOT Streaming).
       - **Example:** A YouTube video about "History" is "Streaming Services". If "Streaming Services" is Unchecked, ALLOW it.
    4. **Search Match:** If the Search Query matches the video topic, assume productive intent -> ALLOW.
    5. **Unchecked Categories:**
       - If a category is **NOT** listed in "Explicitly Blocked Categories", do **NOT** use that category as a reason to block.
       - **Exception:** If the User's Main Prompt explicitly asks to "block distractions", you SHOULD block Social/Entertainment/Games even if unchecked.
       - Only block unlisted categories if they **DIRECTLY CONFLICT** with the User's Main Prompt.
    6. **Reasoning Clarity:**
       - Give simple, direct reasons: just the category name or brief rationale.
       - Good examples: "Social Media", "News & Politics", "Off-topic for Biology", "Matches search".
       - Bad examples: "Social Media is blocked", "This is a blocked category", "Blocked because...".
    `;

    try {
        const result = await model.generateContent(finalPrompt);
        const response = await result.response;
        const text = response.text().trim().replace(/```json/g, '').replace(/```/g, ''); // Clean markdown

        try {
            const jsonResponse = JSON.parse(text);
            return {
                decision: jsonResponse.decision?.toUpperCase() || 'BLOCK',
                reason: jsonResponse.reason || 'AI Decision'
            };
        } catch (e) {
            console.error("AI JSON Parse Error:", e);
            // Fallback if JSON fails
            if (text.toUpperCase().includes('ALLOW')) return { decision: 'ALLOW', reason: 'AI Allowed (Parse Error)' };
            return { decision: 'BLOCK', reason: 'AI Blocked (Parse Error)' };
        }
    } catch (error) {
        // Enhanced error logging for debugging
        console.error('❌ AI Error Details:');
        console.error('   Message:', error.message);
        console.error('   Name:', error.name);
        console.error('   Status:', error.status || 'N/A');
        console.error('   Code:', error.code || 'N/A');
        if (error.message?.includes('429') || error.message?.includes('quota') || error.message?.includes('exhausted')) {
            console.error('   ⚠️ RATE LIMIT DETECTED - Consider reducing API calls or upgrading tier');
        }
        if (error.message?.includes('safety') || error.message?.includes('blocked')) {
            console.error('   ⚠️ CONTENT SAFETY BLOCK - The page content may have triggered safety filters');
        }
        console.error('   URL being checked:', url);
        console.error('   Full Error:', error);
        return { decision: 'BLOCK', reason: 'AI Error' };
    }
}

// --- API Endpoint: Check URL ---
app.post('/check-url', verifyToken, async (req, res) => {
    requestCount++;
    const pageData = req.body;
    const url = pageData?.url;
    const userId = req.user.id; // From middleware

    // --- DETAILED DUPLICATE TRACKING ---
    const normalizedUrl = url ? url.split('?')[0].replace(/\/$/, '') : 'unknown';
    console.log(`\n📥 [REQ #${requestCount}] /check-url`);
    console.log(`   URL: ${normalizedUrl}`);
    console.log(`   Title: ${pageData?.title || 'N/A'}`);
    console.log(`   Time: ${new Date().toISOString()}`);

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
            // PRIVACY: await logBlockingEvent({ userId, url, decision: 'ALLOW', reason: 'Search Engine', pageTitle: pageData?.title });
            return res.json({ decision: 'ALLOW' });
        }

        // 3. YouTube Browsing
        if (hostname.endsWith('youtube.com')) {
            if (!pathname.startsWith('/watch') && !pathname.startsWith('/shorts')) {
                // PRIVACY: await logBlockingEvent({ userId, url, decision: 'ALLOW', reason: 'YouTube Navigation', pageTitle: pageData?.title });
                return res.json({ decision: 'ALLOW' });
            }
        }

        // 4. User Lists
        if (baseDomain && allow_list.some(d => baseDomain === d || baseDomain.endsWith('.' + d))) {
            // PRIVACY: await logBlockingEvent({ userId, url, decision: 'ALLOW', reason: 'Matched Allow List', pageTitle: pageData?.title });
            return res.json({ decision: 'ALLOW' });
        }

        if (baseDomain && block_list.some(d => baseDomain === d || baseDomain.endsWith('.' + d))) {
            // PRIVACY: await logBlockingEvent({ userId, url, decision: 'BLOCK', reason: 'Matched Block List', pageTitle: pageData?.title });
            return res.json({ decision: 'BLOCK', reason: 'On block list' });
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
                // PRIVACY: await logBlockingEvent({ userId, url, decision: 'BLOCK', reason: 'Category: Short-Form', pageTitle: pageData?.title || 'YouTube Short' });
                return res.json({ decision: 'BLOCK', reason: 'Short-form content' });

                // 3. User has NOT blocked shorts and is NOT searching.
            } else {
                // Allow it silently without logging to prevent clutter.
                console.log("Shorts Circuit: Allowed (Category Unchecked)");
                return res.json({ decision: 'ALLOW', cacheVersion: globalCacheVersion });
            }
        }

        // 5. AI Check
        console.log("Proceeding to AI Check...");
        console.log("DEBUG: Rule Data:", {
            prompt: ruleData.prompt,
            categories: ruleData.blocked_categories,
            hasPrompt: ruleData.prompt && ruleData.prompt.trim().length > 0,
            hasCategories: ruleData.blocked_categories && Object.values(ruleData.blocked_categories).some(v => v === true)
        });

        const aiResult = await getAIDecision(pageData, ruleData);
        console.log("DEBUG: AI Result:", aiResult);
        // aiResult is now { decision: "...", reason: "..." }

        let logTitle = pageData?.title || "Unknown Page";
        if (pageData.searchQuery) logTitle += ` [Search: '${pageData.searchQuery}']`;

        // PRIVACY: await logBlockingEvent({ userId, url, decision: aiResult.decision, reason: aiResult.reason, pageTitle: logTitle });
        res.json({ decision: aiResult.decision, reason: aiResult.reason, cacheVersion: globalCacheVersion });

    } catch (err) {
        console.error("Server Error:", err.message);
        // PRIVACY: await logBlockingEvent({ userId, url, decision: 'BLOCK', reason: 'Server Error', pageTitle: pageData?.title });
        res.status(500).json({ error: "Internal Server Error" });
    }
});

// --- Heartbeat ---


// --- API Endpoint: Manual Log (for Shorts Session) ---
// PRIVACY NOTE: This endpoint no longer logs to database - blocks are stored locally in extension
app.post('/log-event', verifyToken, async (req, res) => {
    // PRIVACY: URL logging removed - blocks logged locally in extension only
    // Previously logged shorts sessions to DB, now just acknowledge receipt
    res.json({ success: true, message: 'Block logged locally in extension' });
});

// --- API Endpoint: Clear History ---
app.post('/clear-history', verifyToken, async (req, res) => {
    const userId = req.user.id;
    console.log(`Clearing history for user: ${userId}`);

    if (!process.env.SUPABASE_SERVICE_ROLE_KEY) {
        console.error("❌ ERROR: SUPABASE_SERVICE_ROLE_KEY is missing. Cannot delete history.");
        return res.status(500).json({ error: "Server misconfiguration: Missing Service Role Key" });
    }

    try {
        const { error, count } = await supabaseAdmin
            .from('blocking_log')
            .delete({ count: 'exact' }) // Request count of deleted rows
            .eq('user_id', userId);

        if (error) {
            console.error("Supabase Delete Error:", error);
            throw error;
        }

        console.log(`History cleared. Deleted ${count} rows.`);

        // Force cache clear on all extensions
        globalCacheVersion = Date.now();
        console.log(`Cache version updated to: ${globalCacheVersion}`);

        res.json({ success: true, deletedCount: count, cacheVersion: globalCacheVersion });
    } catch (e) {
        console.error("Error clearing history:", e);
        res.status(500).json({ error: e.message || "Database error" });
    }
});

const nodemailer = require('nodemailer');

// --- API Endpoint: Report Bug ---
app.post('/report-bug', async (req, res) => {
    // Note: This endpoint is public (no verifyToken) to allow anonymous reports if needed,
    // but the frontend sends a token if available.
    // Ideally, we should verify token if provided, but for simplicity we'll just accept it.

    const { description, steps, anonymous, user_id, user_email, screenshot_url, timestamp, recipient } = req.body;

    console.log(`\n🐛 BUG REPORT RECEIVED:`);
    console.log(`To: ${recipient}`);
    console.log(`From: ${anonymous ? 'Anonymous' : user_id}`);
    console.log(`Email: ${anonymous ? 'Hidden' : user_email}`);
    console.log(`Screenshot: ${screenshot_url ? 'Yes' : 'No'}`);
    console.log(`Using Service Key: ${!!process.env.SUPABASE_SERVICE_ROLE_KEY}`);

    try {
        // 1. Save to DB
        console.log("Attempting to insert into bug_reports...");
        const { data, error } = await supabaseAdmin.from('bug_reports').insert({
            user_id: anonymous ? null : user_id,
            description,
            steps,
            anonymous,
            recipient,
            screenshot_url: screenshot_url || null,
            created_at: timestamp || new Date().toISOString()
        }).select();

        if (error) {
            console.error("❌ Error saving bug report to DB:", error);
            return res.status(500).json({ error: "DB Error: " + error.message, details: error });
        } else {
            console.log(`✅ Bug report saved to DB. Data:`, data);
        }

        // 2. Send Email
        if (process.env.EMAIL_USER && process.env.EMAIL_PASS) {
            // Strip spaces from password just in case
            const emailPass = process.env.EMAIL_PASS.replace(/\s+/g, '');

            const transporter = nodemailer.createTransport({
                host: process.env.EMAIL_HOST || 'smtp.gmail.com',
                port: process.env.EMAIL_PORT || 587,
                secure: false,
                auth: {
                    user: process.env.EMAIL_USER,
                    pass: emailPass,
                },
            });

            const mailOptions = {
                from: `"Beacon Blocker" <${process.env.EMAIL_USER}>`,
                to: recipient,
                replyTo: user_email || undefined, // Allow replying to the user
                subject: `🐛 Bug Report: ${description.substring(0, 50)}...`,
                text: `
User: ${anonymous ? 'Anonymous' : user_id}
Email: ${anonymous ? 'Hidden' : (user_email || 'Not provided')}

Description:
${description}

Steps to Reproduce:
${steps || 'N/A'}

Screenshot:
${screenshot_url || 'None attached'}

Timestamp: ${timestamp}
                `
            }; await transporter.sendMail(mailOptions);
            console.log(`📧 Email sent to ${mailOptions.to}`);
        } else {
            console.log("⚠️ Email not configured, skipping email notification.");
        }

        res.status(200).json({ success: true, message: 'Bug report saved and email sent (if configured)' });

    } catch (error) {
        console.error("❌ Error processing bug report:", error);
        res.status(500).json({ error: "Server Error: " + error.message });
    }
});

// --- API Endpoint: Delete Account ---
app.post('/delete-account', verifyToken, async (req, res) => {
    const userId = req.user.id;
    console.log(`\n🚨 DELETE ACCOUNT REQUEST for User: ${userId}`);

    if (!process.env.SUPABASE_SERVICE_ROLE_KEY) {
        console.error("❌ ERROR: SUPABASE_SERVICE_ROLE_KEY is missing. Cannot delete account.");
        return res.status(500).json({ error: "Server misconfiguration: Missing Service Role Key" });
    }

    try {
        // 1. Delete User Data (Rules, Logs, Bug Reports)
        // Using supabaseAdmin to bypass RLS
        const { error: rulesError } = await supabaseAdmin.from('rules').delete().eq('user_id', userId);
        if (rulesError) {
            console.error("Error deleting rules:", rulesError);
            throw rulesError;
        }

        const { error: logsError } = await supabaseAdmin.from('blocking_log').delete().eq('user_id', userId);
        if (logsError) {
            console.error("Error deleting logs:", logsError);
            throw logsError;
        }

        const { error: bugsError } = await supabaseAdmin.from('bug_reports').delete().eq('user_id', userId);
        if (bugsError) {
            console.error("Error deleting bug reports:", bugsError);
            // We might want to keep bug reports for history, but for full deletion we remove them.
            // If this fails, we proceed anyway as it's less critical.
        }

        // 2. Delete User Auth Account
        const { error: authError } = await supabaseAdmin.auth.admin.deleteUser(userId);
        if (authError) {
            console.error("Error deleting auth user:", authError);
            throw authError;
        }

        console.log(`✅ Account deleted successfully for ${userId}`);
        res.json({ success: true });

    } catch (error) {
        console.error("❌ Error deleting account:", error);
        res.status(500).json({ error: "Failed to delete account: " + error.message });
    }
});

// --- API Endpoint: Check Email Existence (For better login errors) ---
app.post('/check-email', async (req, res) => {
    const { email } = req.body;
    if (!email) return res.status(400).json({ error: "Missing email" });

    try {
        // Note: listUsers is not efficient for large user bases, but works for this scale.
        // We fetch a page of users. If we had many, we'd need to paginate.
        const { data: { users }, error } = await supabaseAdmin.auth.admin.listUsers({
            page: 1,
            perPage: 1000
        });

        if (error) throw error;

        const exists = users.some(u => u.email.toLowerCase() === email.toLowerCase());
        res.json({ exists });

    } catch (error) {
        console.error("Check Email Error:", error);
        res.status(500).json({ error: error.message });
    }
});

// --- API Endpoint: Test Email (Debug) ---
app.get('/test-email', async (req, res) => {
    if (!process.env.EMAIL_USER || !process.env.EMAIL_PASS) {
        return res.status(400).json({ error: "Missing EMAIL_USER or EMAIL_PASS in .env" });
    }

    try {
        const emailPass = process.env.EMAIL_PASS.replace(/\s+/g, '');
        const transporter = nodemailer.createTransport({
            host: process.env.EMAIL_HOST || 'smtp.gmail.com',
            port: process.env.EMAIL_PORT || 587,
            secure: false,
            auth: {
                user: process.env.EMAIL_USER,
                pass: emailPass,
            },
        });

        await transporter.verify();
        await transporter.sendMail({
            from: process.env.EMAIL_USER,
            to: process.env.EMAIL_USER,
            subject: "Test Email from Beacon Blocker",
            text: "If you see this, your email configuration is working!"
        });

        res.json({ success: true, message: "Email configuration is valid and test email sent!" });
    } catch (error) {
        console.error("Email Test Failed:", error);
        res.status(500).json({
            error: "Email Test Failed",
            message: error.message,
            code: error.code,
            command: error.command,
            response: error.response,
            stack: error.stack
        });
    }
});

app.listen(port, () => {
    console.log(`✅ SERVER IS LIVE on port ${port}`);
});
console.log(`DEBUG: Attempting to listen on port ${port}...`);

// --- DEPRECATED: /classify-url endpoint ---
// This was a duplicate of /check-url and caused double API calls.
// Kept commented for reference but should not be used.
/*
app.post('/classify-url', async (req, res) => {
    try {
        const { pageData, auth } = req.body;

        if (!auth || !auth.access_token) {
            console.log('Request rejected: Missing Auth');
            return res.status(401).json({ decision: 'BLOCK', reason: 'Unauthorized' });
        }

        const { data: { user }, error: authError } = await supabaseAdmin.auth.getUser(auth.access_token);
        if (authError || !user) {
            console.log('Request rejected: Invalid Token');
            return res.status(401).json({ decision: 'BLOCK', reason: 'Invalid Token' });
        }

        const ruleData = await getUserRuleData(user.id);
        const aiResult = await getAIDecision(pageData, ruleData);
        
        console.log(`🤖 AI Decision: ${aiResult.decision} (${aiResult.reason})`);
        res.json(aiResult);

    } catch (error) {
        console.error('Server Error:', error);
        res.status(500).json({ decision: 'BLOCK', reason: 'Server Error' });
    }
});
*/