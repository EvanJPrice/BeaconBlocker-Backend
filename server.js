// FILE: server.js
// VERSION: v6.3 (Shorts Circuit + Nuanced Prompt + Silent System Rules)


// --- Imports ---
require('dotenv').config();
const { GoogleGenerativeAI } = require('@google/generative-ai');
const express = require('express');
const cors = require('cors');
const { createClient } = require('@supabase/supabase-js');
const nodemailer = require('nodemailer');

// --- Setup ---
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
    model: "gemini-flash-latest",
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

    // Basic email validation
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
        return res.status(400).json({ error: 'Invalid email format' });
    }

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
        // Privacy: Avoid logging full URLs in console logs in production
        // console.log(`DEBUG: Attempting to log event for user ${userId} - ${domain}`);

        // Note on Privacy: We store the full URL and Title so the user can see their own history.
        // This table should be protected by RLS so only the user can select their own rows.
        // We use supabaseAdmin here to perform the INSERT (which might bypass RLS on insert),
        // but reads are restricted.

        // Use supabaseAdmin to bypass RLS for insertion
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
            // console.log("✅ Event logged successfully.");
        }
    } catch (err) { console.error("Logging exception:", err.message); }
}

async function getUserRuleData(userId) {
    if (!userId) return null;
    // console.log(`DEBUG: Fetching rules for user ${userId}`);

    // MUST use supabaseAdmin to bypass RLS, as the server has no user session
    const { data, error } = await supabaseAdmin
        .from('rules')
        .select('prompt, blocked_categories, allow_list, block_list')
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
    // console.log("DEBUG: Rule Data:", JSON.stringify(ruleData, null, 2));

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

// --- AI Decision Function ---
async function getAIDecision(pageData, ruleData) {
    const { title, description, h1, url, searchQuery, keywords, bodyText, localTime } = pageData;
    const { prompt: userMainPrompt, blocked_categories } = ruleData;

    console.log(`AI Input: Title='${title}'`);

    // 1. Auto-Allow Exact Matches
    if (searchQuery && title) {
        const cleanSearch = searchQuery.toLowerCase().trim();
        const cleanTitle = title.toLowerCase().trim();
        if (cleanTitle.includes(cleanSearch) || cleanSearch.includes(cleanTitle)) {
            console.log(`Auto-Allow: Search '${cleanSearch}' matches title.`);
            return { decision: 'ALLOW', reason: `Matches search: "${cleanSearch}"` };
        }
    }

    // 2. Default to ALLOW if no rules are set (Passive Mode)
    const hasPrompt = userMainPrompt && userMainPrompt.trim().length > 0;
    const hasCategories = blocked_categories && Object.values(blocked_categories).some(v => v === true);

    console.log("DEBUG: Category Check:", {
        blocked_categories,
        hasCategories,
        values: blocked_categories ? Object.values(blocked_categories) : 'null'
    });

    if (!hasPrompt && !hasCategories) {
        console.log("No rules set. Defaulting to ALLOW (Passive Mode).");
        const debugInfo = `Cats: ${blocked_categories ? Object.keys(blocked_categories).length : 'null'}`;
        return { decision: 'ALLOW', reason: `No rules set (Passive Mode) [${debugInfo}]` };
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
    **CURRENT USER TIME:** "${localTime || 'Unknown'}"
    (If the user's prompt mentions a time limit like "until 5pm", compare it with this time to decide.)
    
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
        "reason": "A short, concise explanation (max 10 words) for the user."
    }

    **CRITICAL INSTRUCTIONS (Priority Order):**
    1. **User's Main Prompt:** Highest priority. If they explicitly allow a topic, ALLOW it.
    2. **Platform Overrides Content (CRITICAL):**
       - If the URL belongs to a known platform, you MUST classify it under that platform's category, regardless of the specific content.
       - **YouTube/Twitch** = **Streaming Services** (NOT Entertainment, NOT Education).
       - **Netflix/Hulu** = **Entertainment** (NOT Streaming).
       - **Example:** A YouTube video about "History" is "Streaming Services". If "Streaming Services" is Unchecked, ALLOW it.
    3. **Search Match:** If the Search Query matches the video topic, assume productive intent -> ALLOW.
    4. **Unchecked Categories:**
       - If a category is **NOT** listed in "Explicitly Blocked Categories", do **NOT** use that category as a reason to block.
       - **Exception:** If the User's Main Prompt explicitly asks to "block distractions", you SHOULD block Social/Entertainment/Games even if unchecked.
       - Only block unlisted categories if they **DIRECTLY CONFLICT** with the User's Main Prompt.
    5. **Reasoning Clarity:**
       - If you **ALLOW** because no rule is violated, set reason to: **"No relevant blocking rules found"**.
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
        console.error('AI Error:', error.message);
        return { decision: 'BLOCK', reason: 'AI Error' };
    }
}

// --- API Endpoint: Check URL ---
app.post('/check-url', verifyToken, async (req, res) => {
    const pageData = req.body;
    const url = pageData?.url;
    const userId = req.user.id; // From middleware

    if (!url) return res.status(400).json({ error: 'Missing URL' });

    // Basic URL validation
    try {
        new URL(url);
    } catch (e) {
        return res.status(400).json({ error: 'Invalid URL format' });
    }

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
            // Log this now!
            await logBlockingEvent({ userId, url, decision: 'ALLOW', reason: 'Search Engine', pageTitle: pageData?.title });
            return res.json({ decision: 'ALLOW' });
        }

        // 3. YouTube Browsing
        if (hostname.endsWith('youtube.com')) {
            if (!pathname.startsWith('/watch') && !pathname.startsWith('/shorts')) {
                // Log navigation too
                await logBlockingEvent({ userId, url, decision: 'ALLOW', reason: 'YouTube Navigation', pageTitle: pageData?.title });
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

        await logBlockingEvent({ userId, url, decision: aiResult.decision, reason: aiResult.reason, pageTitle: logTitle });
        res.json({ decision: aiResult.decision, cacheVersion: globalCacheVersion });

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

// --- API Endpoint: Report Bug ---
app.post('/report-bug', async (req, res) => {
    // Note: This endpoint is public (no verifyToken) to allow anonymous reports if needed,
    // but the frontend sends a token if available.

    const { description, steps, anonymous, user_id, user_email, timestamp, recipient } = req.body;

    // Basic Validation
    if (!description || description.length > 5000) {
        return res.status(400).json({ error: "Description is missing or too long." });
    }

    console.log(`\n🐛 BUG REPORT RECEIVED:`);
    // Privacy: Only log essential info
    console.log(`To: ${recipient}`);
    console.log(`From: ${anonymous ? 'Anonymous' : 'User ' + user_id}`);

    try {
        // 1. Save to DB
        console.log("Attempting to insert into bug_reports...");
        const { data, error } = await supabaseAdmin.from('bug_reports').insert({
            user_id: anonymous ? null : user_id,
            description,
            steps,
            anonymous,
            recipient,
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

// --- API Endpoint: Check Email Existence ---
// DEPRECATED/REMOVED due to privacy concerns (User Enumeration Risk).
// app.post('/check-email', ...)

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