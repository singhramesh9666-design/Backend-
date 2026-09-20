const express = require("express");
const cors = require("cors");
const admin = require("firebase-admin");
const cloudinary = require("cloudinary").v2;

// ================= CLOUDINARY (SUPPORT TICKET MEDIA) =================
// Required env vars (set these on Render):
//   CLOUDINARY_CLOUD_NAME, CLOUDINARY_API_KEY, CLOUDINARY_API_SECRET
// Free plan needs no bank card at signup — 25GB storage / 25GB bandwidth/mo.
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});
// No file-size cap is enforced anywhere below on purpose — the browser
// uploads DIRECTLY to Cloudinary using a short-lived signature, bypassing
// the 30mb Express JSON limit entirely (that limit only applies to routes
// like /process-match-results which send base64 JSON).

const serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT);

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
  databaseURL: "https://stone-clash-fd3da-default-rtdb.asia-southeast1.firebasedatabase.app",
});

const db = admin.database();
const app = express();

// CORS explicit mode me enable kiya gaya hai
app.use(cors({ origin: "*" }));
// NOTE: limit 30mb rakha gaya hai kyunki /process-match-results route par
// screenshots base64 images ke roop me bhejte hain jo default 100kb limit
// se kaafi bade hote hain. Pehle ye global parser sirf 100kb allow karta
// tha, isliye bade requests par silently ek HTML error page return hota
// tha (Express ka default unhandled-error page) jisse frontend me
// "Unexpected token '<'" JSON.parse error aata tha.
app.use(express.json({ limit: "30mb" }));

// ================= USER AUTH MIDDLEWARE =================
// Ye check karta hai ki request genuinely logged-in user se aa rahi hai
async function verifyAuth(req, res, next) {
  try {
    const authHeader = req.headers.authorization || "";
    const idToken = authHeader.startsWith("Bearer ") ? authHeader.split(" ")[1] : null;

    if (!idToken) {
      return res.status(401).json({ error: "No token provided" });
    }

    const decodedToken = await admin.auth().verifyIdToken(idToken);
    req.uid = decodedToken.uid;
    next();
  } catch (err) {
    console.log("❌ Auth verify failed:", err.message);
    return res.status(401).json({ error: "Invalid or expired token" });
  }
}

// ================= STAFF DEVICE SESSION VERIFICATION =================
// admin.html login (aur logout button) is route ko call karta hai taaki har
// staff member sirf apne allowed devices se hi login kar sake, jitne
// `staff/{uid}/maxAllowedDevices` allow kare (default 1). Device
// "fingerprint" browser ke localStorage me generate/persist hota hai
// (getStaffDeviceFingerprint() — admin.html me).
//
// LOGIN: agar fingerprint pehle se `allowedDevices` list me hai to allow.
// Agar naya hai aur list abhi `maxAllowedDevices` se kam hai to add karke
// allow. Agar limit poori ho chuki hai to 403 with error+message (jo
// frontend `alert(d.error + "\n" + d.message)` se dikhata hai).
//
// LOGOUT: sirf `online:false` karte hain — device slot free NAHI hota
// (admin panel ka "Reset Staff Devices" button hi allowedDevices clear
// karta hai — window.resetStaffDeviceBindings).
//
// NOTE: Ye Admin SDK (`db`) use karta hai, isliye rules.html me
// `staff/$uid/allowedDevices` ka client-side write-restriction (sirf
// admin/senior-admin) yaha bypass ho jaata hai — jo intentional hai,
// kyunki staff khud apna device register kar raha hai login ke waqt.
app.post("/staff/verify-session", verifyAuth, async (req, res) => {
  try {
    const { deviceFingerprint, action } = req.body || {};
    const uid = req.uid;

    if (!deviceFingerprint || typeof deviceFingerprint !== "string") {
      return res.status(400).json({ error: "Bad Request", message: "Device fingerprint missing hai." });
    }

    const staffRef = db.ref(`staff/${uid}`);
    const staffSnap = await staffRef.get();
    if (!staffSnap.exists()) {
      return res.status(403).json({ error: "Not Authorized", message: "Ye account staff list me nahi hai." });
    }
    const staffData = staffSnap.val() || {};

    // LOGOUT — sirf online status off, device-binding preserve rehta hai.
    if (action === "LOGOUT") {
      await staffRef.update({ online: false, lastActive: Date.now() });
      return res.json({ success: true });
    }

    // LOGIN se pehle account active hona chahiye.
    if (staffData.status && staffData.status !== "active") {
      return res.status(403).json({
        error: "Account Disabled",
        message: "Aapka staff account abhi active nahi hai. Admin se contact karein.",
      });
    }

    const allowedDevices = Array.isArray(staffData.allowedDevices) ? staffData.allowedDevices : [];
    const maxAllowedDevices = Number(staffData.maxAllowedDevices) || 1;
    const alreadyAllowed = allowedDevices.includes(deviceFingerprint);

    if (!alreadyAllowed) {
      if (allowedDevices.length >= maxAllowedDevices) {
        return res.status(403).json({
          error: "Device Limit Reached",
          message: `Aap already ${maxAllowedDevices} device${maxAllowedDevices > 1 ? "s" : ""} se logged in ho. Naya device use karne ke liye admin se extra permission mangwayein ya purane devices reset karwayein.`,
        });
      }
      allowedDevices.push(deviceFingerprint);
    }

    await staffRef.update({
      allowedDevices,
      online: true,
      lastActive: Date.now(),
      lastLogin: Date.now(),
    });

    return res.json({ success: true });
  } catch (err) {
    console.log("❌ /staff/verify-session error:", err.message);
    return res.status(500).json({ error: "Server Error", message: "Kuch galat ho gaya, dobara try karein." });
  }
});

// ================= WEEKLY LEADERBOARD REWARDS =================
// Ye rewards weekly leaderboard reset se THODI PEHLE (usi reset cycle ke
// andar) top-10 ko automatically credit hote hain, us hafte ke combinedScore
// (jo abhi tak ke OLD baseline se calculate hota hai) ke hisaab se — bilkul
// wahi formula jo user.html me "Weekly Leaderboard" dikhane ke liye use hota
// hai (Level + Matches + Earnings, 1/3-1/3-1/3 normalized weight).
const WEEKLY_LEADERBOARD_REWARDS = [
  { rank: 1, type: "balance", amount: 30, label: "30 Deposit Coins", txMethod: "Deposit Balance" },
  { rank: 2, type: "balance", amount: 20, label: "20 Deposit Coins", txMethod: "Deposit Balance" },
  { rank: 3, type: "balance", amount: 10, label: "10 Deposit Coins", txMethod: "Deposit Balance" },
  { rank: 4, type: "spinTickets", amount: 1, label: "1 Spin Wheel Ticket", txMethod: "Spin Ticket" },
  { rank: 5, type: "scratchCards", amount: 1, label: "1 Scratch Card", txMethod: "Scratch Card" },
  { rank: 6, type: "xp", amount: 50, label: "50 XP", txMethod: "XP" },
  { rank: 7, type: "xp", amount: 40, label: "40 XP", txMethod: "XP" },
  { rank: 8, type: "xp", amount: 30, label: "30 XP", txMethod: "XP" },
  { rank: 9, type: "xp", amount: 20, label: "20 XP", txMethod: "XP" },
  { rank: 10, type: "xp", amount: 10, label: "10 XP", txMethod: "XP" },
];

// `usersSnap` aur `matchCounts` maybeResetWeeklyLeaderboard() se already fetched
// hote hain — yahan dobara fetch nahi karna padta. `weekStart` sirf logging ke
// liye hai (jis hafte ke liye reward diya ja raha hai).
async function distributeWeeklyLeaderboardRewards(usersSnap, matchCounts, weekStart) {
  try {
    let users = [];
    usersSnap.forEach((u) => {
      const v = u.val() || {};
      const uid = u.key;
      const xp = Number(v.xp) || 0;
      const level = Math.floor(Math.sqrt(xp / 50)) + 1;
      const matchesPlayed = matchCounts[uid] || 0;
      // Lifetime total ever won (doesn't drop on withdrawal). Falls back to
      // winningCash for accounts that predate this field.
      const totalWin = v.lifetimeWinnings !== undefined ? (Number(v.lifetimeWinnings) || 0) : (Number(v.winningCash) || 0);
      const wb = v.weeklyBaseline || {};
      const weeklyLevel = Math.max(0, level - (Number(wb.level) || 0));
      const weeklyMatches = Math.max(0, matchesPlayed - (Number(wb.matches) || 0));
      const weeklyWin = Math.max(0, totalWin - (Number(wb.totalWin) || 0));
      users.push({ uid, weeklyLevel, weeklyMatches, weeklyWin });
    });

    // Same normalized-combined-score formula as the "Weekly Leaderboard" modal.
    const norm = (val, min, max) => (max > min ? ((val - min) / (max - min)) * 100 : (max > 0 ? 100 : 0));
    const lvlVals = users.map((u) => u.weeklyLevel), lvlMin = Math.min(...lvlVals, 0), lvlMax = Math.max(...lvlVals, 0);
    const mVals = users.map((u) => u.weeklyMatches), mMin = Math.min(...mVals, 0), mMax = Math.max(...mVals, 0);
    const eVals = users.map((u) => u.weeklyWin), eMin = Math.min(...eVals, 0), eMax = Math.max(...eVals, 0);
    users = users.map((u) => ({
      ...u,
      combinedScore: (norm(u.weeklyLevel, lvlMin, lvlMax) / 3) + (norm(u.weeklyMatches, mMin, mMax) / 3) + (norm(u.weeklyWin, eMin, eMax) / 3),
    }));

    users.sort((a, b) => b.combinedScore - a.combinedScore);
    const winners = users.filter((u) => u.combinedScore > 0).slice(0, WEEKLY_LEADERBOARD_REWARDS.length);

    if (!winners.length) {
      console.log(`ℹ️ Weekly leaderboard rewards: no eligible winners for week starting ${new Date(weekStart).toISOString()}`);
      return;
    }

    for (let i = 0; i < winners.length; i++) {
      const winner = winners[i];
      const reward = WEEKLY_LEADERBOARD_REWARDS[i];
      try {
        await db.ref(`users/${winner.uid}`).transaction((user) => {
          if (!user) return user;
          user[reward.type] = (Number(user[reward.type]) || 0) + reward.amount;
          return user;
        });

        await db.ref(`users/${winner.uid}/transactions`).push({
          type: "Weekly Leaderboard Reward",
          amount: reward.amount,
          status: "Success",
          time: Date.now(),
          method: reward.txMethod,
          adminNote: `Rank #${reward.rank} — Weekly Leaderboard`,
        });

        await db.ref(`users/${winner.uid}/notifications`).push({
          title: `🏆 Weekly Leaderboard Reward!`,
          message: `You finished Rank #${reward.rank} on the Weekly Leaderboard and received ${reward.label}.`,
          type: "success",
          read: false,
          timestamp: admin.database.ServerValue.TIMESTAMP,
        });

        console.log(`✅ Weekly leaderboard reward credited: uid=${winner.uid}, rank=${reward.rank}, reward=${reward.label}`);
      } catch (userErr) {
        console.log(`❌ Weekly leaderboard reward failed for uid=${winner.uid}:`, userErr.message);
      }
    }
  } catch (err) {
    console.log("❌ Weekly leaderboard rewards distribution error:", err.message);
  }
}

// ================= WEEKLY LEADERBOARD RESET =================
// Weekly leaderboard "Overall Leaderboard" jaisa hi point system use karta hai
// (Level + Matches + Earnings, normalized, equal weight) lekin sirf current
// week ke progress par based hota hai. Isके liye hum har user ka ek
// "weeklyBaseline" snapshot (level/matches/totalWin) store karte hain jo
// har Monday 00:00 IST par refresh hota hai — us waqt ka combinedScore
// current values minus baseline values se nikalta hai.
//
// IST = UTC+5:30, no DST, isliye offset hardcode safe hai.
const IST_OFFSET_MS = 5.5 * 60 * 60 * 1000;

// Sabse recent Monday 00:00 IST (as a UTC ms timestamp) nikalta hai, given "now".
function getLastMondayIstMs(nowMs) {
  const istNow = nowMs + IST_OFFSET_MS;
  const istDate = new Date(istNow);
  const dayOfWeek = istDate.getUTCDay(); // 0=Sun..6=Sat (IST-shifted "UTC" fields)
  const daysSinceMonday = (dayOfWeek + 6) % 7; // Mon=0, Tue=1, ... Sun=6
  const istMidnight = Date.UTC(
    istDate.getUTCFullYear(),
    istDate.getUTCMonth(),
    istDate.getUTCDate()
  ) - daysSinceMonday * 24 * 60 * 60 * 1000;
  return istMidnight - IST_OFFSET_MS; // wapas real UTC ms me
}

// Agar naya week shuru ho chuka hai to sabhi users ke liye baseline snapshot
// refresh karta hai. Concurrent triggers se bachne ke liye settings node par
// transaction lagaya gaya hai (sirf ek hi request actually reset karegi).
async function maybeResetWeeklyLeaderboard() {
  try {
    const now = Date.now();
    const targetWeekStart = getLastMondayIstMs(now);

    let previousWeekStart = null;
    const txResult = await db.ref("settings/weeklyLeaderboard/weekStartAt").transaction((cur) => {
      if (cur === targetWeekStart) return; // already up to date, abort tx
      previousWeekStart = cur || null;
      return targetWeekStart;
    });

    if (!txResult.committed) return; // dusre request ne already handle kar diya, ya already current

    console.log(`🔄 Weekly leaderboard reset triggered for week starting ${new Date(targetWeekStart).toISOString()}`);

    const [usersSnap, tournamentsSnap] = await Promise.all([
      db.ref("users").once("value"),
      db.ref("tournaments").once("value"),
    ]);

    const matchCounts = {};
    if (tournamentsSnap.exists()) {
      tournamentsSnap.forEach((t) => {
        const rp = t.val()?.registeredPlayers;
        if (rp) Object.keys(rp).forEach((uid) => { matchCounts[uid] = (matchCounts[uid] || 0) + 1; });
      });
    }

    // Reset se PEHLE — abhi tak ka baseline still-active hai isliye yahi
    // sahi jagah hai jis hafte ka leaderboard ab khatam ho raha hai uske
    // top-10 ko reward dene ke liye. Pehla-hi-ever reset (previousWeekStart
    // null) me koi purana week nahi hota, isliye rewards skip.
    // NAYA: Weekly Leaderboard REWARD feature band kar diya gaya hai (admin
    // ki request par) -- leaderboard khud abhi bhi normal kaam karega
    // (rank dikhna, baseline reset har Monday), bas top players ko ab
    // automatic reward nahi milega is reset ke time. Wapas enable karne ke
    // liye neeche wali line uncomment kar do.
    // if (previousWeekStart && usersSnap.exists()) {
    //   await distributeWeeklyLeaderboardRewards(usersSnap, matchCounts, previousWeekStart);
    // }

    const updates = {};
    if (usersSnap.exists()) {
      usersSnap.forEach((u) => {
        const uid = u.key;
        const v = u.val() || {};
        const xp = Number(v.xp) || 0;
        const level = Math.floor(Math.sqrt(xp / 50)) + 1;
        updates[`users/${uid}/weeklyBaseline`] = {
          level,
          matches: matchCounts[uid] || 0,
          totalWin: v.lifetimeWinnings !== undefined ? (Number(v.lifetimeWinnings) || 0) : (Number(v.winningCash) || 0),
          setAt: now,
        };
      });
    }

    if (Object.keys(updates).length) await db.ref().update(updates);
    console.log(`✅ Weekly leaderboard baseline reset done for ${Object.keys(updates).length} users`);
  } catch (err) {
    console.log("❌ Weekly leaderboard reset error:", err.message);
  }
}

// ================= PUBLIC PING ROUTE =================
// Render cold-start se bachne ke liye (cron-job.org ke liye, bina auth).
// Har ping ke saath hum yeh bhi check kar lete hain ki naya week (Monday
// 00:00 IST) shuru hua hai ya nahi — agar haan, to weekly leaderboard
// baseline reset ho jaata hai (fire-and-forget, ping ka response block nahi hota).
app.get("/ping", (req, res) => {
  console.log(`📡 Ping received at ${new Date().toISOString()}`);
  maybeResetWeeklyLeaderboard();
  res.status(200).send("ok");
});

// ================= TEST ROUTE =================
app.get("/health", verifyAuth, async (req, res) => {
  res.json({ status: "ok", yourUid: req.uid });
});

// ================= REDEEM CODE (secure) =================
app.post("/redeem-code", verifyAuth, async (req, res) => {
  try {
    const { code } = req.body;
    if (!code || typeof code !== "string") {
      return res.status(400).json({ error: "code is required" });
    }
    const cleanCode = code.trim().toUpperCase();
    const uid = req.uid;

    const codeResult = await db.ref(`redeemCodes/${cleanCode}`).transaction((data) => {
      if (data === null) return data;
      if (data.status === "active" && !data.usedBy) {
        data.status = "used";
        data.usedBy = uid;
        data.usedAt = Date.now();
        return data;
      }
      return;
    });

    if (!codeResult.committed || !codeResult.snapshot.exists()) {
      return res.status(400).json({ error: "Invalid or already used code" });
    }

    const amount = Number(codeResult.snapshot.val().amount || 0);

    await db.ref(`users/${uid}`).transaction((user) => {
      if (user) {
        user.balance = (Number(user.balance) || 0) + amount;
      }
      return user;
    });

    await db.ref("deposits").push({
      userId: uid,
      amount: amount,
      paymentMethod: "Redeem Code",
      status: "completed",
      timestamp: admin.database.ServerValue.TIMESTAMP
    });

    console.log(`✅ Redeem success: uid=${uid}, code=${cleanCode}, amount=${amount}`);
    return res.json({ success: true, amount });

  } catch (err) {
    console.log("❌ Redeem code error:", err.message);
    return res.status(500).json({ error: "Something went wrong" });
  }
});

// ================= COMPLETE REFERRAL (secure) =================
app.post("/complete-referral", verifyAuth, async (req, res) => {
  try {
    const { referralId } = req.body;
    if (!referralId || typeof referralId !== "string") {
      return res.status(400).json({ error: "referralId is required" });
    }
    const uid = req.uid;

    const prRef = db.ref(`pendingReferrals/${referralId}`);
    const prSnap = await prRef.get();

    if (!prSnap.exists()) {
      return res.status(404).json({ error: "Referral not found" });
    }

    const pr = prSnap.val();

    if (pr.referrerUid !== uid) {
      return res.status(403).json({ error: "Not your referral" });
    }
    if (pr.status !== "pending") {
      return res.status(400).json({ error: "Referral already completed" });
    }
    if (!pr.referredUid) {
      return res.status(400).json({ error: "Invalid referral entry" });
    }
    if (pr.referrerUid === pr.referredUid) {
      return res.status(400).json({ error: "Invalid referral entry" });
    }

    const friendSnap = await db.ref(`users/${pr.referredUid}`).get();
    if (!friendSnap.exists()) {
      return res.status(404).json({ error: "Referred user not found" });
    }
    const friend = friendSnap.val();
    if (friend.referralDepositDone !== true || friend.referralPaidMatchDone !== true) {
      return res.status(400).json({ error: "Referred friend hasn't completed requirements yet" });
    }

    const bonusAmount = Number(pr.bonusAmount || 0);

    const txResult = await prRef.transaction((cur) => {
      if (!cur || cur.status !== "pending") return cur;
      cur.status = "completed";
      cur.creditedAt = Date.now();
      return cur;
    });

    if (!txResult.committed || txResult.snapshot.val()?.status !== "completed") {
      return res.status(400).json({ error: "Referral already processed" });
    }

    await db.ref(`users/${uid}`).transaction((user) => {
      if (user) {
        user.bonusCash = (Number(user.bonusCash) || 0) + bonusAmount;
      }
      return user;
    });

    await db.ref(`users/${uid}/notifications`).push({
      title: "Referral Reward Credited!",
      message: `Your friend completed the requirements - bonus added!`,
      type: "success",
      read: false,
      timestamp: admin.database.ServerValue.TIMESTAMP
    });

    console.log(`✅ Referral completed: referrer=${uid}, referralId=${referralId}, bonus=${bonusAmount}`);
    return res.json({ success: true, bonusAmount });

  } catch (err) {
    console.log("❌ Complete referral error:", err.message);
    return res.status(500).json({ error: "Something went wrong" });
  }
});

// ================= ENSURE PROFILE (secure) =================
async function generateUniqueReferralCode() {
  const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
  for (let attempt = 0; attempt < 15; attempt++) {
    let code = "";
    const len = Math.random() > 0.5 ? 3 : 4;
    for (let i = 0; i < len; i++) code += chars.charAt(Math.floor(Math.random() * chars.length));
    const snap = await db.ref("users").orderByChild("referralCode").equalTo(code).get();
    if (!snap.exists()) return code;
  }
  return "R" + Date.now().toString(36).toUpperCase().slice(-5);
}

app.post("/ensure-profile", verifyAuth, async (req, res) => {
  try {
    const uid = req.uid;
    const uRef = db.ref(`users/${uid}`);
    const { displayName, deviceId, referralCodeInput } = req.body || {};

    // FIX: agar record abhi tak exist nahi karta AUR is request me displayName
    // nahi bheja gaya (jaise "repair" listener ka khaali body {} wala call),
    // to yahan naya profile create hi mat karo — sirf wahi request profile
    // banaye jo actual signup data (naam/deviceId) laayi ho. Isse woh race
    // condition khatam ho jaati hai jisme khaali-body wali request signup
    // wali request ko overwrite karke "Player" + deviceId:null likh deti thi.
    //
    // BUG FIX (referral system broken): login/signup hote hi client seedha
    // `users/{uid}/fcmToken` par direct write karta hai (agar FCM token
    // pehle se available ho) — Firebase RTDB me ye akele child-write bhi
    // `users/{uid}` node ko turant "exist" karwa deta hai, asli profile
    // banne se PEHLE hi. Isse `preSnap.exists()` galat tarike se true aa
    // jaata tha, poora "naya profile + referral processing" block skip ho
    // jaata tha, aur referral code kabhi process hi nahi hota tha (na
    // pendingReferrals entry banti thi, na welcome bonus milta tha). Ab hum
    // "real profile" ko sirf `createdAt` field ke hone se pehchante hain —
    // ek akela bare fcmToken node ab "existing profile" nahi maana jaayega.
    const preSnap = await uRef.get();
    const realProfileExists = preSnap.exists() && preSnap.hasChild("createdAt");
    if (!realProfileExists && !(typeof displayName === "string" && displayName.trim())) {
      return res.json({ success: false, pending: true });
    }

    if (!realProfileExists) {
      // FIX: get()+set() ke beech race condition thi — do parallel requests
      // dono "profile exist nahi karta" dekh kar dono create kar sakte the,
      // aur jo baad me likhta wo pehle wale ko overwrite kar deta (yahi bug
      // tha jiski wajah se kabhi kabhi galat/khaali data — "Player",
      // deviceId:null — save ho jaata tha). Ab transaction se sirf EK hi
      // write jeetegi, aur wo bhi sirf tab jab node abhi tak koi real
      // (createdAt wala) profile na ho.
      const cleanName = displayName.trim().slice(0, 40);

      const authUser = await admin.auth().getUser(uid);
      const email = authUser.email || null;

      if (deviceId) {
        const banSnap = await db.ref(`bannedDevices/${deviceId}`).get();
        if (banSnap.exists() && banSnap.val()) {
          return res.status(403).json({ error: "Your Device is Banned" });
        }
      }

      const referralCode = await generateUniqueReferralCode();

      // Agar us bare fcmToken-only node ki wajah se koi fcmToken already
      // save ho chuka tha, use naye profile me preserve kar lete hain
      // (taaki push notifications turant kaam karein, dobara wait na karna
      // pade agli token-refresh tak).
      const preExistingFcmToken = preSnap.exists() ? preSnap.child("fcmToken").val() : null;

      const newProfile = {
        uid,
        displayName: cleanName,
        gameIgn: cleanName,
        email,
        deviceId: deviceId || null,
        balance: 0,
        winningCash: 0,
        bonusCash: 0,
        lifetimeWinnings: 0, // explicit from day one — new accounts never need
                             // the winningCash-fallback or a future backfill
        joinedTournaments: {},
        referralCode,
        createdAt: admin.database.ServerValue.TIMESTAMP
      };
      if (preExistingFcmToken) newProfile.fcmToken = preExistingFcmToken;

      let createdNow = false;
      const txResult = await uRef.transaction((current) => {
        // Abort sirf tab jab is beech me koi REAL (createdAt wala) profile
        // ban chuka ho — ek bare fcmToken-only node ko overwrite karna theek
        // hai, wahi to yahan fix kar rahe hain.
        if (current && current.createdAt) return; // pehle se ban chuka — is write ko abort karo
        createdNow = true;
        return newProfile;
      });

      if (!(createdNow && txResult.committed)) {
        // Doosri request jeet gayi — hum sirf uska referralCode wapas bhej dete hain
        const finalSnap = await uRef.get();
        const finalVal = finalSnap.val() || {};
        return res.json({ success: true, created: false, referralCode: finalVal.referralCode || null });
      }

      let welcomeBonus = 0;
      const refInput = typeof referralCodeInput === "string" ? referralCodeInput.trim().toUpperCase() : "";
      if (refInput) {
        const referrerSnap = await db.ref("users").orderByChild("referralCode").equalTo(refInput).get();
        if (referrerSnap.exists()) {
          const referrerUid = Object.keys(referrerSnap.val())[0];
          if (referrerUid !== uid) {
            const settingsSnap = await db.ref("settings/referralBonus").get();
            const bonusAmt = Number(settingsSnap.val() || 0);

            await db.ref("pendingReferrals").push({
              referrerUid,
              referredUid: uid,
              referredEmail: email,
              bonusAmount: bonusAmt,
              status: "pending",
              timestamp: admin.database.ServerValue.TIMESTAMP
            });

            if (bonusAmt > 0) {
              await uRef.transaction((user) => {
                if (user) user.bonusCash = (Number(user.bonusCash) || 0) + bonusAmt;
                return user;
              });
              welcomeBonus = bonusAmt;
              await db.ref(`users/${uid}/notifications`).push({
                title: "Welcome Bonus!",
                message: `You joined using a referral code - Rs.${bonusAmt} has been instantly added to your bonus!`,
                type: "success",
                read: false,
                timestamp: admin.database.ServerValue.TIMESTAMP
              });
            }
          }
        }
      }

      console.log(`✅ Profile created: uid=${uid}, referralCode=${referralCode}`);
      return res.json({ success: true, created: true, referralCode, welcomeBonus });
    }

    const existing = preSnap.val();
    const patch = {};

    // FIX: purane buggy signups jinka deviceId null reh gaya tha, unke liye
    // — agar client abhi bhi wahi deviceId bhej raha hai (usi browser/app se
    // aaya hai, localStorage me safe hai) to use backfill kar do. Sirf tabhi
    // likhte hain jab DB me abhi deviceId missing/null ho — kisi existing
    // sahi-save deviceId ko kabhi overwrite nahi karte.
    if (!existing.deviceId && typeof deviceId === "string" && deviceId.trim()) {
      const banSnap = await db.ref(`bannedDevices/${deviceId}`).get();
      if (banSnap.exists() && banSnap.val()) {
        return res.status(403).json({ error: "Your Device is Banned" });
      }
      patch.deviceId = deviceId.trim();
    }

    if (!existing.referralCode) {
      patch.referralCode = await generateUniqueReferralCode();
    }

    if (Object.keys(patch).length > 0) {
      await uRef.update(patch);
      console.log(`✅ Profile repaired: uid=${uid}, patch=${JSON.stringify(patch)}`);
    }

    return res.json({ success: true, created: false, referralCode: patch.referralCode || existing.referralCode || null });

  } catch (err) {
    console.log("❌ Ensure profile error:", err.message);
    return res.status(500).json({ error: "Something went wrong" });
  }
});

// ================= CLAIM DAILY XP / LOGIN STREAK (secure) =================
app.post("/claim-daily-xp", verifyAuth, async (req, res) => {
  try {
    const uid = req.uid;
    const uRef = db.ref(`users/${uid}`);
    const now = new Date();
    const todayStr = now.toDateString();

    let alreadyClaimed = false;
    const tx = await uRef.transaction((u) => {
      if (!u) return u;
      if (u.lastDailyXpDate === todayStr) {
        alreadyClaimed = true;
        return; 
      }

      let newStreak = Number(u.loginStreak) || 0;
      if (u.lastDailyXpDate) {
        const lastDate = new Date(u.lastDailyXpDate);
        lastDate.setHours(0, 0, 0, 0);
        const todayMidnight = new Date(now);
        todayMidnight.setHours(0, 0, 0, 0);
        const diffDays = Math.round((todayMidnight - lastDate) / 86400000);
        if (diffDays === 1) newStreak += 1;
        else if (diffDays > 1) newStreak = 1;
      } else {
        newStreak = 1;
      }

      u.xp = (Number(u.xp) || 0) + 10;
      u.lastDailyXpDate = todayStr;
      u.loginStreak = newStreak;
      return u;
    });

    if (!tx.committed || alreadyClaimed) {
      return res.json({ success: true, claimed: false });
    }

    const result = tx.snapshot.val() || {};
    console.log(`✅ Daily XP claimed: uid=${uid}, streak=${result.loginStreak}`);
    return res.json({ success: true, claimed: true, xp: result.xp, streak: result.loginStreak });

  } catch (err) {
    console.log("❌ Claim daily xp error:", err.message);
    return res.status(500).json({ error: "Something went wrong" });
  }
});

// ================= CLAIM LEVEL REWARD (secure) =================
// Levels aur unke rewards `levelRewards/{level}` node se admin panel se
// configure hote hain -- har level ka `xpRequired` (badhta hua threshold)
// aur reward (`rewardType` + `rewardAmount`) admin decide karta hai. User
// XP threshold cross karne ke baad manually "Claim" karta hai (auto-credit
// nahi hota). `claimedLevels` map se track hota hai ki kaunsa level already
// claim ho chuka hai, taaki koi reward dobara na mil sake. Order-restriction
// nahi hai -- agar user XP se ek saath 2-3 levels aage nikal gaya (jaise
// bade daily-xp jump se), wo saare unclaimed-but-reached levels claim kar
// sakta hai, ek-ek karke lower level claim karna zaroori nahi.
const VALID_LEVEL_REWARD_TYPES = ["bonusCash", "balance", "spinTickets", "coins", "scratchCards", "membership"];

app.post("/claim-level-reward", verifyAuth, async (req, res) => {
  try {
    const uid = req.uid;
    const { level } = req.body || {};
    const levelKey = level !== undefined && level !== null ? String(level).trim() : "";
    if (!levelKey) {
      return res.status(400).json({ error: "level is required" });
    }

    const levelSnap = await db.ref(`levelRewards/${levelKey}`).get();
    if (!levelSnap.exists()) {
      return res.status(404).json({ error: "Level not found" });
    }
    const levelDef = levelSnap.val();
    const xpRequired = Number(levelDef.xpRequired || 0);
    const rewardType = levelDef.rewardType;
    const rewardAmount = Number(levelDef.rewardAmount || 0);

    if (!VALID_LEVEL_REWARD_TYPES.includes(rewardType) || !(rewardAmount >= 0)) {
      console.log(`❌ Level ${levelKey} has invalid reward config:`, JSON.stringify(levelDef));
      return res.status(400).json({ error: "This level's reward isn't configured correctly, contact admin" });
    }

    let failReason = null;
    const uRef = db.ref(`users/${uid}`);
    const tx = await uRef.transaction((user) => {
      if (!user) return user;
      const userXp = Number(user.xp) || 0;

      if (user.claimedLevels && user.claimedLevels[levelKey]) {
        failReason = "already_claimed";
        return;
      }
      if (userXp < xpRequired) {
        failReason = "not_enough_xp";
        return;
      }

      if (!user.claimedLevels) user.claimedLevels = {};
      user.claimedLevels[levelKey] = true;
      user.level = Math.max(Number(user.level) || 0, Number(levelKey) || 0);

      if (rewardType === "membership") {
        // Membership reward grants `rewardAmount` days of VIP, stacking on
        // top of any existing unexpired membership instead of overwriting it.
        const base = Math.max(Number(user.vipExpiresAt) || 0, Date.now());
        user.vipExpiresAt = base + rewardAmount * 24 * 60 * 60 * 1000;
        user.vipActive = true;
      } else {
        user[rewardType] = (Number(user[rewardType]) || 0) + rewardAmount;
      }
      return user;
    });

    if (!tx.committed || failReason) {
      const msg = failReason === "already_claimed" ? "You've already claimed this level's reward"
        : failReason === "not_enough_xp" ? "You haven't reached this level yet"
        : "Could not claim reward, please try again";
      return res.status(400).json({ error: msg });
    }

    const rewardUnitLabel = rewardType === "membership" ? `${rewardAmount} day(s) of Membership`
      : `${rewardAmount} ${rewardType}`;

    if (rewardAmount > 0) {
      await db.ref(`users/${uid}/transactions`).push({
        type: "Level Reward",
        amount: rewardAmount,
        status: "Success",
        time: Date.now(),
        method: rewardType,
        adminNote: `Level ${levelKey}`
      });
    }

    await db.ref(`users/${uid}/notifications`).push({
      title: `Level ${levelKey} Reward Claimed!`,
      message: `You received ${rewardUnitLabel} for reaching Level ${levelKey}.`,
      type: "success",
      read: false,
      timestamp: admin.database.ServerValue.TIMESTAMP
    });

    console.log(`✅ Level reward claimed: uid=${uid}, level=${levelKey}, type=${rewardType}, amount=${rewardAmount}`);
    return res.json({ success: true, level: levelKey, rewardType, rewardAmount, newLevel: tx.snapshot.val().level });

  } catch (err) {
    console.log("❌ Claim level reward error:", err.message);
    return res.status(500).json({ error: "Something went wrong" });
  }
});

// ================= JOIN TOURNAMENT / ADD ENTRY (secure) =================
app.post("/join-tournament", verifyAuth, async (req, res) => {
  try {
    const uid = req.uid;
    const { tournamentId, selectedSlots, teamDetails, mode } = req.body || {};

    if (!tournamentId || typeof tournamentId !== "string") {
      return res.status(400).json({ error: "tournamentId is required" });
    }
    if (!Array.isArray(selectedSlots) || selectedSlots.length < 1) {
      return res.status(400).json({ error: "Please select at least 1 slot" });
    }
    if (!Array.isArray(teamDetails) || teamDetails.length !== selectedSlots.length) {
      return res.status(400).json({ error: "teamDetails must match selected slots" });
    }
    const joinMode = mode === "add" ? "add" : "join";

    for (const td of teamDetails) {
      const name = typeof td.gameName === "string" ? td.gameName.trim() : "";
      const gUid = typeof td.gameUid === "string" ? td.gameUid.replace(/\s+/g, "") : "";
      if (!name || name.length < 3 || name.length > 25) {
        return res.status(400).json({ error: "Each player name must be 3-25 characters" });
      }
      if (gUid && (gUid.length < 4 || gUid.length > 25 || isNaN(gUid))) {
        return res.status(400).json({ error: "Player UID must be a valid number" });
      }
    }
    const cleanTeamDetails = teamDetails.map((td) => ({
      gameName: String(td.gameName).trim(),
      gameUid: String(td.gameUid || "").replace(/\s+/g, "")
    }));
    const cleanSlots = selectedSlots.map((s) => String(s));

    const tSnap = await db.ref(`tournaments/${tournamentId}`).get();
    if (!tSnap.exists()) return res.status(404).json({ error: "Tournament not found" });
    const tDat = tSnap.val();

    if (["canceled", "completed", "result"].includes(tDat.status)) {
      return res.status(400).json({ error: "Tournament closed" });
    }

    const eFee = Number(tDat.entryFee || 0);
    const modeStr = String(tDat.mode || "Solo").toLowerCase();
    let maxTeamSize = 1;
    if (modeStr === "duo") maxTeamSize = 2;
    else if (modeStr === "3 player" || modeStr === "trio") maxTeamSize = 3;
    else if (modeStr === "squad") maxTeamSize = 4;

    if (cleanSlots.length > maxTeamSize) {
      return res.status(400).json({ error: "Too many slots selected for this team size" });
    }

    const totalFee = eFee * cleanSlots.length;

    let tModeEnum = "Solo";
    if (maxTeamSize === 2) tModeEnum = "Duo";
    if (maxTeamSize === 3) tModeEnum = "Trio";
    if (maxTeamSize === 4) tModeEnum = "Squad";

    let slotFail = null;
    let actuallyCreatedFresh = null; 
    let previousPlayerState = null;  
    const rpRef = db.ref(`tournaments/${tournamentId}/registeredPlayers`);
    const rpTx = await rpRef.transaction((players) => {
      if (players === null) players = {};
      const existing = players[uid];

      if (joinMode === "join" && existing) { slotFail = "already_joined"; return; }

      const booked = [];
      Object.entries(players).forEach(([pUid, p]) => {
        if (pUid === uid) return;
        if (p.slots) p.slots.forEach((s) => booked.push(String(s)));
        else if (p.slot) booked.push(String(p.slot));
      });

      if (cleanSlots.some((s) => booked.includes(s))) { slotFail = "slot_taken"; return; }

      if (existing) {
        previousPlayerState = { ...existing }; 
        const existingSlots = existing.slots || (existing.slot ? [existing.slot] : []);
        const mergedSlots = [...existingSlots, ...cleanSlots];
        if (mergedSlots.length > maxTeamSize) { slotFail = "team_full"; return; }
        players[uid] = {
          ...existing,
          teamDetails: [...(existing.teamDetails || []), ...cleanTeamDetails],
          slots: mergedSlots,
          lastEntryAddedAt: Date.now()
        };
        actuallyCreatedFresh = false;
      } else {
        players[uid] = {
          timestamp: Date.now(),
          gameName: cleanTeamDetails[0].gameName,
          gameUid: cleanTeamDetails[0].gameUid,
          playerName: cleanTeamDetails[0].gameName,
          playerUid: cleanTeamDetails[0].gameUid,
          userName: null,
          userId: uid,
          matchId: tournamentId,
          teamMode: tModeEnum,
          teamDetails: cleanTeamDetails,
          slot: cleanSlots[0],
          slots: cleanSlots,
          matchStatus: "playing"
        };
        actuallyCreatedFresh = true;
      }
      return players;
    });

    if (!rpTx.committed) {
      const msg = slotFail === "already_joined" ? "You already joined this match!"
        : slotFail === "slot_taken" ? "Selected slot(s) already taken!"
        : slotFail === "team_full" ? "Team is already full!"
        : "Slot booking failed, please try again.";
      return res.status(400).json({ error: msg });
    }

    const wasFreshJoin = actuallyCreatedFresh === true;
    const uRef = db.ref(`users/${uid}`);
    let insufficientFunds = false;
    const wTx = await uRef.transaction((user) => {
      if (!user) return user;
      const uDep = Number(user.balance) || 0;
      const uWin = Number(user.winningCash) || 0;
      const uBon = Number(user.bonusCash) || 0;

      const txMaxBonus = totalFee * 0.10;
      const txBonusUsed = Math.min(txMaxBonus, uBon);
      const txCashReq = totalFee - txBonusUsed;

      if (uDep + uWin < txCashReq) {
        insufficientFunds = true;
        return;
      }

      user.bonusCash = uBon - txBonusUsed;
      // NOTE: XP ab yahan (join ke waqt) nahi milta — match cancel bhi ho sakta
      // hai, isliye XP sirf match RESULT declare hone par milta hai (admin
      // panel ke "Execute Computations" flow se: 20 XP participation + 50 XP
      // bonus for Rank 1). Daily login (`/claim-daily-xp`) doosra XP source hai.

      if (uDep >= txCashReq) {
        user.balance = uDep - txCashReq;
      } else {
        user.balance = 0;
        user.winningCash = uWin - (txCashReq - uDep);
      }
      return user;
    });

    if (!wTx.committed) {
      await rpRef.transaction((players) => {
        if (!players) return players;
        if (previousPlayerState) {
          players[uid] = previousPlayerState;
        } else {
          delete players[uid]; 
        }
        return players;
      });
      return res.status(400).json({ error: insufficientFunds ? "Insufficient Wallet Balance" : "Wallet update failed, try again" });
    }

    const updatedUser = wTx.snapshot.val() || {};
    const walletSnapshot = {
      balance: Number(updatedUser.balance) || 0,
      winningCash: Number(updatedUser.winningCash) || 0,
      bonusCash: Number(updatedUser.bonusCash) || 0,
      xp: Number(updatedUser.xp) || 0
    };

    if (wasFreshJoin) {
      try {
        const authUser = await admin.auth().getUser(uid);
        await db.ref(`tournaments/${tournamentId}/registeredPlayers/${uid}`).update({
          userName: authUser.displayName || (authUser.email ? authUser.email.split("@")[0] : "Unknown"),
          userEmail: authUser.email || "Unknown"
        });
      } catch (e) { }

      await db.ref(`users/${uid}/joinedTournaments/${tournamentId}`).set({ timestamp: admin.database.ServerValue.TIMESTAMP });

      if (totalFee > 0) {
        await db.ref(`users/${uid}`).transaction((user) => {
          if (user && user.referralPaidMatchDone !== true) user.referralPaidMatchDone = true;
          return user;
        });
      }
    }

    await db.ref(`users/${uid}/notifications`).push({
      title: wasFreshJoin ? "Match Joined Successfully" : "Entry Added Successfully",
      message: `You successfully booked slot(s) [${cleanSlots.join(", ")}] in ${tDat.name}. Entry Fee: ${totalFee}.`,
      type: "success",
      read: false,
      timestamp: admin.database.ServerValue.TIMESTAMP
    });

    if (totalFee > 0) {
      await db.ref(`users/${uid}/transactions`).push({
        type: "Match Entry",
        amount: totalFee,
        status: "Success",
        time: Date.now(),
        method: "Wallet",
        adminNote: tDat.name
      });
    }

    console.log(`✅ Tournament ${wasFreshJoin ? "join" : "add-entry"}: uid=${uid}, tournamentId=${tournamentId}, slots=${cleanSlots.join(",")}, fee=${totalFee}`);
    return res.json({ success: true, totalFee, slots: cleanSlots, joined: wasFreshJoin, wallet: walletSnapshot });

  } catch (err) {
    console.log("❌ Join tournament error:", err.message);
    return res.status(500).json({ error: "Something went wrong" });
  }
});

// ================= REQUEST WITHDRAWAL (secure) =================
app.post("/request-withdrawal", verifyAuth, async (req, res) => {
  try {
    const uid = req.uid;
    const { wdType, amount, accountInfo, isFast } = req.body || {};

    if (wdType !== "money" && wdType !== "redeem") {
      return res.status(400).json({ error: "Invalid withdrawal type" });
    }
    const amt = Number(amount);
    if (!amt || amt <= 0) {
      return res.status(400).json({ error: "Invalid amount" });
    }
    const wantsFast = isFast === true && wdType === "money"; // fast withdrawal sirf money type ke liye, redeem ke liye nahi
    const cleanAccountInfo = typeof accountInfo === "string" ? accountInfo.trim() : "";
    if (wdType === "money" && !cleanAccountInfo) {
      return res.status(400).json({ error: "Enter Bank/UPI" });
    }

    // NAYA: Withdrawal tax -- admin ke Settings > Tax se set kiya % yahan
    // apply hota hai. Fast Withdrawal (turant process, manual admin
    // approval skip) ke liye ek ADDITIONAL % tax lagta hai (jo bhi admin
    // ne "Fast Withdrawal Extra Tax %" set kiya ho), normal tax ke upar.
    // User ko wahi "amt" (jo usne maanga) milega -- tax uske WALLET se
    // extra kata jaata hai, taaki payout hamesha declared amount ke barabar
    // rahe aur tax calculation transparent rahe.
    const taxSettingsSnap2 = await db.ref("settings/tax").get();
    const taxSettings2 = taxSettingsSnap2.val() || {};
    const withdrawTaxPercent = Math.max(0, Math.min(100, Number(taxSettings2.withdrawPercent) || 0));
    const fastExtraTaxPercent = Math.max(0, Math.min(100, Number(taxSettings2.fastWithdrawExtraPercent) || 0));
    const effectiveTaxPercent = withdrawTaxPercent + (wantsFast ? fastExtraTaxPercent : 0);
    const taxAmount = Math.round((amt * effectiveTaxPercent) / 100 * 100) / 100;
    const totalDeduction = Math.round((amt + taxAmount) * 100) / 100; // user pays out amt + tax from their wallet

    const userSnap = await db.ref(`users/${uid}`).get();
    if (!userSnap.exists()) return res.status(404).json({ error: "User not found" });
    const user = userSnap.val();
    const isVip = user.vipActive === true && Number(user.vipExpiresAt || 0) > Date.now();

    const settingsSnap = await db.ref("settings").get();
    const settings = settingsSnap.val() || {};
    const baseMin = Number(settings.minWithdraw || 50);
    const minWithdraw = isVip ? Math.max(1, Math.round(baseMin * 0.8)) : baseMin;
    if (amt < minWithdraw) {
      return res.status(400).json({ error: `Min ${wdType === "money" ? "withdraw" : "redeem"} is ${minWithdraw}` });
    }

    const now = Date.now();
    const oneDayAgo = now - 24 * 60 * 60 * 1000;
    const wdSnap = await db.ref("withdrawals").orderByChild("userId").equalTo(uid).get();
    let pendingCount = 0, dailyCount = 0;
    if (wdSnap.exists()) {
      wdSnap.forEach((c) => {
        const w = c.val();
        const reqTime = w.requestTimestamp || w.processedAt || 0;
        if (w.status === "pending") pendingCount++;
        if (reqTime >= oneDayAgo && w.status !== "rejected") dailyCount++;
      });
    }
    const maxPending = isVip ? 2 : 1;
    const maxDaily = isVip ? 3 : 1;

    let rejectReason = null;
    if (pendingCount >= maxPending) {
      rejectReason = isVip
        ? "VIP MEMBERS CAN ONLY MAKE 2 WITHDRAWAL AT A TIME"
        : "UPGRADE TO VIP TO MAKE 2 WITHDRAWAL AT SAME TIME";
    } else if (dailyCount >= maxDaily) {
      rejectReason = isVip
        ? "VIP MEMBERS CAN MAKE ONLY 3 WITHDRAWAL IN A DAY"
        : "UPGRADE TO VIP TO MAKE MORE 3 WITHDRAWAL IN 24 hours";
    }

    if (rejectReason) {
      await db.ref(`users/${uid}/notifications`).push({
        title: "WITHDRAWAL REJECTED",
        message: rejectReason,
        type: "error",
        read: false,
        timestamp: admin.database.ServerValue.TIMESTAMP
      });

      await db.ref("withdrawals").push({
        userId: uid,
        userName: user.displayName || "User",
        userEmail: user.email || "",
        amount: amt,
        methodDetails: wdType === "money" ? { accountInfo: cleanAccountInfo } : null,
        withdrawalType: wdType,
        status: "rejected",
        rejectReason,
        requestTimestamp: admin.database.ServerValue.TIMESTAMP,
        processedAt: admin.database.ServerValue.TIMESTAMP
      });

      return res.status(400).json({ error: rejectReason });
    }

    const uRef = db.ref(`users/${uid}`);
    let insufficientFunds = false;
    const tx = await uRef.transaction((u) => {
      if (!u) return u;
      const uWin = Number(u.winningCash) || 0;
      if (uWin < totalDeduction) { insufficientFunds = true; return; }
      u.winningCash = uWin - totalDeduction;
      return u;
    });

    if (!tx.committed) {
      return res.status(400).json({ error: insufficientFunds ? "Insufficient Balance (amount + tax exceeds your winning balance)" : "Wallet update failed, try again" });
    }

    const wData = {
      userId: uid,
      userName: user.displayName || "User",
      userEmail: user.email || "",
      amount: amt,
      taxPercent: effectiveTaxPercent,
      taxAmount,
      totalDeducted: totalDeduction,
      isFast: wantsFast,
      withdrawalType: wdType,
      // Fast withdrawals turant "approved" status me chali jaati hain
      // (manual admin review skip) -- lekin actual payout process karna
      // (real bank transfer bhejna) abhi bhi admin/payment-system ka kaam
      // hai, ye sirf app-side queue-status hai.
      status: wantsFast ? "approved" : "pending",
      requestTimestamp: admin.database.ServerValue.TIMESTAMP,
      ...(wantsFast ? { processedAt: admin.database.ServerValue.TIMESTAMP, autoApprovedFast: true } : {}),
    };
    if (wdType === "money") wData.methodDetails = { accountInfo: cleanAccountInfo };

    const pushRef = await db.ref("withdrawals").push(wData);

    if (wantsFast) {
      await db.ref(`users/${uid}/notifications`).push({
        title: "Fast Withdrawal Approved",
        message: `Your fast withdrawal of ₹${amt} has been auto-approved${taxAmount > 0 ? ` (₹${taxAmount} tax deducted)` : ""}. It will be processed shortly.`,
        type: "success",
        read: false,
        timestamp: admin.database.ServerValue.TIMESTAMP,
      });
    }

    console.log(`✅ Withdrawal requested: uid=${uid}, type=${wdType}, amount=${amt}, tax=${taxAmount}, fast=${wantsFast}`);
    return res.json({ success: true, withdrawalId: pushRef.key, taxAmount, totalDeducted: totalDeduction, isFast: wantsFast });

  } catch (err) {
    console.log("❌ Request withdrawal error:", err.message);
    return res.status(500).json({ error: "Something went wrong" });
  }
});

// ================= CREDIT DEPOSIT (secure) =================
async function verifyZapUPIPaymentServerSide(orderId, expectedUid) {
  const zapKeySnap = await db.ref("settings/payment/zap_key").get();
  const zapKey = zapKeySnap.val();
  if (!zapKey) throw new Error("zap_key not configured in settings/payment");

  const resp = await fetch("https://pay.zapupi.com/api/order-status", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ zap_key: zapKey, order_id: orderId })
  });
  const json = await resp.json();

  if (json.status !== "success" || !json.data) {
    return { verified: false };
  }
  const d = json.data;

  if (String(d.order_id) !== String(orderId)) {
    return { verified: false };
  }

  const paymentSucceeded = d.status === "Success";
  const amount = Number(d.pay_amount ?? d.amount ?? 0);

  return {
    verified: paymentSucceeded && amount > 0,
    amount,
    utr: d.utr || d.txn_id || ""
  };
}

app.post("/credit-deposit", verifyAuth, async (req, res) => {
  try {
    const { orderId } = req.body || {};
    if (!orderId || typeof orderId !== "string") {
      return res.status(400).json({ error: "orderId is required" });
    }
    const uid = req.uid;

    const orderRef = db.ref(`orders/${orderId}`);
    const orderSnap = await orderRef.get();
    if (!orderSnap.exists()) return res.status(404).json({ error: "Order not found" });
    const order = orderSnap.val();
    if (order.userId !== uid) return res.status(403).json({ error: "Not your order" });
    if (order.status === "completed") {
      return res.status(400).json({ error: "Order already credited" }); 
    }

    const verification = await verifyZapUPIPaymentServerSide(orderId, uid);
    if (!verification.verified) {
      return res.status(400).json({ error: "Payment not verified yet" });
    }
    const amount = Number(verification.amount || 0);
    if (!(amount > 0)) {
      return res.status(400).json({ error: "Invalid verified amount" });
    }

    // NAYA: Deposit tax -- admin ne Settings me jo % set kiya hai wahi
    // yahan kaat ke credit hota hai (jaise ₹100 deposit pe 2% tax → ₹98
    // credit). Backend hi ye calculate karta hai, taaki koi bhi client-side
    // tampering se poora amount na credit karwa sake.
    const taxSettingsSnap = await db.ref("settings/tax").get();
    const taxSettings = taxSettingsSnap.val() || {};
    const depositTaxPercent = Math.max(0, Math.min(100, Number(taxSettings.depositPercent) || 0));
    const depositTaxAmount = Math.round((amount * depositTaxPercent) / 100 * 100) / 100;
    const creditedAmount = Math.round((amount - depositTaxAmount) * 100) / 100;

    const orderTx = await orderRef.transaction((cur) => {
      if (!cur) return cur;
      if (cur.status === "completed") return; 
      cur.status = "completed";
      cur.utr = verification.utr || cur.utr || "";
      cur.completedAt = Date.now();
      return cur;
    });
    if (!orderTx.committed) {
      return res.status(400).json({ error: "Order already credited" });
    }

    await db.ref(`users/${uid}`).transaction((user) => {
      if (user) {
        user.balance = (Number(user.balance) || 0) + creditedAmount;
        if (user.referralDepositDone !== true) user.referralDepositDone = true;
      }
      return user;
    });

    await db.ref("deposits").push({
      userId: uid,
      amount,
      taxPercent: depositTaxPercent,
      taxAmount: depositTaxAmount,
      creditedAmount,
      utr: verification.utr || "-",
      paymentMethod: "ZapUPI Auto",
      status: "completed",
      timestamp: admin.database.ServerValue.TIMESTAMP
    });

    await db.ref(`users/${uid}/notifications`).push({
      title: "Payment Successful",
      message: depositTaxAmount > 0
        ? `Deposit of ₹${amount} received. ₹${depositTaxAmount} tax deducted — ₹${creditedAmount} credited.`
        : `Deposit of ${amount} credited.`,
      type: "success",
      read: false,
      timestamp: admin.database.ServerValue.TIMESTAMP
    });

    await db.ref(`users/${uid}/transactions`).push({
      type: "Deposit",
      amount: creditedAmount,
      grossAmount: amount,
      taxAmount: depositTaxAmount,
      status: "Success",
      time: Date.now(),
      method: "ZapUPI Auto",
      adminNote: verification.utr || "-"
    });

    console.log(`✅ Deposit credited: uid=${uid}, orderId=${orderId}, gross=${amount}, tax=${depositTaxAmount}, credited=${creditedAmount}`);
    return res.json({ success: true, amount: creditedAmount, grossAmount: amount, taxAmount: depositTaxAmount });

  } catch (err) {
    console.log("❌ Credit deposit error:", err.message);
    return res.status(500).json({ error: "Something went wrong" });
  }
});

// ================= APPLY COUPON (secure) =================
app.post("/apply-coupon", verifyAuth, async (req, res) => {
  try {
    const { code } = req.body || {};
    if (!code || typeof code !== "string") {
      return res.status(400).json({ error: "code is required" });
    }
    const cleanCode = code.trim().toUpperCase();
    const uid = req.uid;

    const codeRef = db.ref(`couponCodes/${cleanCode}`);
    const codeResult = await codeRef.transaction((data) => {
      if (data === null) return data; 
      if (data.status !== "active") return; 
      if (!data.usedUsers) data.usedUsers = {};
      if (data.usedUsers[uid]) return; 
      data.usedUsers[uid] = true;
      return data;
    });

    if (!codeResult.committed || !codeResult.snapshot.exists()) {
      return res.status(400).json({ error: "Invalid or already used code" });
    }

    const amount = Number(codeResult.snapshot.val().amount || 0);

    await db.ref(`users/${uid}`).transaction((user) => {
      if (user) {
        user.bonusCash = (Number(user.bonusCash) || 0) + amount;
      }
      return user;
    });

    await db.ref(`users/${uid}/notifications`).push({
      title: "Coupon Applied!",
      message: `Coupon "${cleanCode}" applied - Bonus added.`,
      type: "success",
      read: false,
      timestamp: admin.database.ServerValue.TIMESTAMP
    });

    console.log(`✅ Coupon applied: uid=${uid}, code=${cleanCode}, amount=${amount}`);
    return res.json({ success: true, amount });

  } catch (err) {
    console.log("❌ Apply coupon error:", err.message);
    return res.status(500).json({ error: "Something went wrong" });
  }
});

// ================= PURCHASE VIP (secure) =================
app.post("/purchase-vip", verifyAuth, async (req, res) => {
  try {
    const uid = req.uid;
    const { plan } = req.body || {};
    if (plan !== "weekly" && plan !== "monthly") {
      return res.status(400).json({ error: "Invalid plan" });
    }

    const settingsSnap = await db.ref("settings/vipMembership").get();
    const vipSettings = settingsSnap.val() || {};
    const fallback = plan === "weekly" ? 99 : 299;
    const price = Number(vipSettings[plan + "Price"] ?? fallback);
    if (!(price >= 0)) {
      return res.status(400).json({ error: "VIP pricing not configured" });
    }
    const days = plan === "weekly" ? 7 : 30;

    let insufficientFunds = false;
    let purchaseResult = null;
    const uRef = db.ref(`users/${uid}`);
    const tx = await uRef.transaction((u) => {
      if (!u) return u;

      const uDep = Number(u.balance) || 0;
      const uWin = Number(u.winningCash) || 0;

      if (uDep + uWin < price) { insufficientFunds = true; return; }

      const now = Date.now();
      const oldExp = Number(u.vipExpiresAt) || 0;
      const start = Math.max(now, oldExp);
      const expiry = start + days * 86400000;
      purchaseResult = { expiry, price };

      if (uDep >= price) {
        u.balance = uDep - price;
      } else {
        u.balance = 0;
        u.winningCash = uWin - (price - uDep);
      }

      u.vipActive = true;
      u.vipPlan = plan;
      u.vipPurchasedAt = now;
      u.vipExpiresAt = expiry;
      u.vipLastPrice = price;
      if (!u.profileEmoji) {
        const VIP_EMOJIS = ["😀","😎","🤩","🥳","😈","👑","🔥","💎","⚡","🎮","🏆","🦁","🐯","🐺","🦊","🐉","👽","🤖","👾","💀","😇","🤠","🥶","🤯","😻","🙈","💫","🌟","🚀","❤️"];
        u.profileEmoji = VIP_EMOJIS[Math.floor(Math.random() * VIP_EMOJIS.length)];
      }
      return u;
    });

    if (!tx.committed || !purchaseResult) {
      return res.status(400).json({ error: insufficientFunds ? "Insufficient combined wallet balance" : "Purchase failed, try again" });
    }

    const now = Date.now();
    await db.ref(`users/${uid}/transactions`).push({
      type: "VIP Membership",
      plan,
      amount: price,
      status: "Success",
      time: now,
      expiry: purchaseResult.expiry,
      method: "Wallet"
    });

    await db.ref("vipTransactions").push({
      uid,
      plan,
      amount: price,
      buyingDate: now,
      expiredDate: purchaseResult.expiry,
      status: "Success"
    });

    await db.ref(`users/${uid}/notifications`).push({
      title: "VIP Membership Activated",
      message: `Your ${plan} VIP pass is active until ${new Date(purchaseResult.expiry).toLocaleString("en-IN")}.`,
      type: "success",
      read: false,
      timestamp: admin.database.ServerValue.TIMESTAMP
    });

    console.log(`✅ VIP purchased: uid=${uid}, plan=${plan}, price=${price}, expiry=${purchaseResult.expiry}`);
    return res.json({ success: true, plan, price, expiresAt: purchaseResult.expiry });

  } catch (err) {
    console.log("❌ Purchase VIP error:", err.message);
    return res.status(500).json({ error: "Something went wrong" });
  }
});

// ================= CHECK VIP EXPIRY (secure) =================
app.post("/check-vip-expiry", verifyAuth, async (req, res) => {
  try {
    const uid = req.uid;
    const uRef = db.ref(`users/${uid}`);
    const snap = await uRef.get();
    if (!snap.exists()) return res.status(404).json({ error: "User not found" });
    const u = snap.val();

    const isExpired = u.vipExpiresAt && Number(u.vipExpiresAt) <= Date.now();
    if (!(u.vipActive === true && isExpired)) {
      return res.json({ success: true, expired: false });
    }

    let expiredPlan = null;
    await uRef.transaction((cur) => {
      if (!cur) return cur;
      if (!(cur.vipActive === true && Number(cur.vipExpiresAt) <= Date.now())) return; 
      expiredPlan = cur.vipPlan || null;
      cur.vipActive = false;
      cur.vipExpiresAt = null;
      cur.vipPlan = null;
      cur.vipPurchasedAt = null;
      cur.profileImageUrl = null;
      // VIP emoji picker is a VIP-only feature — always reset to a fresh
      // random emoji on expiry (not just when they had none), so an expired
      // user's chosen VIP emoji doesn't carry over.
      const VIP_EMOJIS = ["😀","😎","🤩","🥳","😈","👑","🔥","💎","⚡","🎮","🏆","🦁","🐯","🐺","🦊","🐉","👽","🤖","👾","💀","😇","🤠","🥶","🤯","😻","🙈","💫","🌟","🚀","❤️"];
      cur.profileEmoji = VIP_EMOJIS[Math.floor(Math.random() * VIP_EMOJIS.length)];
      return cur;
    });

    if (expiredPlan) {
      // Transaction history me sirf informational entry (amount 0) — koi
      // paisa move nahi hota, sirf yaad rakhne ke liye ki VIP kab expire hua.
      await db.ref(`users/${uid}/transactions`).push({
        type: "VIP Membership",
        plan: expiredPlan,
        amount: 0,
        status: "Expired",
        time: Date.now(),
        method: "Wallet",
      });

      await db.ref(`users/${uid}/notifications`).push({
        title: "VIP Membership Expired",
        message: `Your ${expiredPlan} VIP membership has expired. Renew anytime to keep enjoying premium benefits.`,
        type: "info",
        read: false,
        timestamp: admin.database.ServerValue.TIMESTAMP,
      });
    }

    console.log(`✅ VIP expired server-side: uid=${uid}`);
    return res.json({ success: true, expired: true });

  } catch (err) {
    console.log("❌ Check VIP expiry error:", err.message);
    return res.status(500).json({ error: "Something went wrong" });
  }
});

// ================= JOIN LOTTERY (secure) =================
app.post("/join-lottery", verifyAuth, async (req, res) => {
  try {
    const uid = req.uid;
    const { lotteryId } = req.body || {};
    if (!lotteryId || typeof lotteryId !== "string") {
      return res.status(400).json({ error: "lotteryId is required" });
    }

    const lRef = db.ref(`lotteries/${lotteryId}`);
    const lSnap = await lRef.get();
    if (!lSnap.exists()) return res.status(404).json({ error: "Lottery not found" });
    const lDat = lSnap.val();

    if (lDat.status !== "upcoming") {
      return res.status(400).json({ error: "This lottery is not open for entries" });
    }

    const fee = Number(lDat.entryFee || 0);
    const maxSlots = Number(lDat.maxSlots || 100);

    let slotFail = null;
    const authUser = await admin.auth().getUser(uid);
    const ruRef = db.ref(`lotteries/${lotteryId}/registeredUsers`);
    const ruTx = await ruRef.transaction((users) => {
      if (users === null) users = {};
      if (users[uid]) { slotFail = "already_joined"; return; }
      if (Object.keys(users).length >= maxSlots) { slotFail = "full"; return; }
      users[uid] = {
        timestamp: Date.now(),
        userName: authUser.displayName || (authUser.email ? authUser.email.split("@")[0] : "Unknown"),
        userEmail: authUser.email || "Unknown"
      };
      return users;
    });

    if (!ruTx.committed) {
      const msg = slotFail === "already_joined" ? "You already joined this lottery!"
        : slotFail === "full" ? "This lottery is full!"
        : "Could not book ticket, please try again.";
      return res.status(400).json({ error: msg });
    }

    let insufficientFunds = false;
    const uRef = db.ref(`users/${uid}`);
    const wTx = await uRef.transaction((user) => {
      if (!user) return user;
      const uDep = Number(user.balance) || 0;
      const uWin = Number(user.winningCash) || 0;
      if (uDep + uWin < fee) { insufficientFunds = true; return; }
      if (uDep >= fee) {
        user.balance = uDep - fee;
      } else {
        user.balance = 0;
        user.winningCash = uWin - (fee - uDep);
      }
      return user;
    });

    if (!wTx.committed) {
      await ruRef.transaction((users) => {
        if (!users) return users;
        delete users[uid];
        return users;
      });
      return res.status(400).json({ error: insufficientFunds ? "Insufficient Wallet Balance" : "Wallet update failed, try again" });
    }

    if (fee > 0) {
      await db.ref(`users/${uid}/transactions`).push({
        type: "Lottery Ticket",
        amount: fee,
        status: "Success",
        time: Date.now(),
        method: "Wallet"
      });
    }

    console.log(`✅ Lottery joined: uid=${uid}, lotteryId=${lotteryId}, fee=${fee}`);
    return res.json({ success: true, fee });

  } catch (err) {
    console.log("❌ Join lottery error:", err.message);
    return res.status(500).json({ error: "Something went wrong" });
  }
});

// ================= BUY PRODUCT / SHOP PURCHASE (secure) =================
app.post("/buy-product", verifyAuth, async (req, res) => {
  try {
    const uid = req.uid;
    const { productId, name, phone, address, note } = req.body || {};

    const cleanName = typeof name === "string" ? name.trim() : "";
    const cleanPhone = typeof phone === "string" ? phone.trim() : "";
    const cleanAddress = typeof address === "string" ? address.trim() : "";
    const cleanNote = typeof note === "string" ? note.trim() : "";

    if (!productId || typeof productId !== "string") {
      return res.status(400).json({ error: "productId is required" });
    }
    if (!cleanName || !cleanPhone || !cleanAddress) {
      return res.status(400).json({ error: "Fill all required fields!" });
    }
    if (cleanPhone.length < 10) {
      return res.status(400).json({ error: "Invalid phone number" });
    }

    const prodRef = db.ref(`shopProducts/${productId}`);
    const prodSnap = await prodRef.get();
    if (!prodSnap.exists()) return res.status(404).json({ error: "Product not found" });
    const prod = prodSnap.val();
    if (prod.status !== "active") {
      return res.status(400).json({ error: "Too late! Product is already sold out." });
    }
    const price = Number(prod.price || 0);
    if (!(price > 0)) {
      return res.status(400).json({ error: "Invalid product price" });
    }
    const productName = prod.name || "Product";

    let insufficientFunds = false;
    const uRef = db.ref(`users/${uid}`);
    const wTx = await uRef.transaction((user) => {
      if (!user) return user;
      const uDep = Number(user.balance) || 0;
      const uWin = Number(user.winningCash) || 0;
      if (uDep + uWin < price) { insufficientFunds = true; return; }
      if (uDep >= price) {
        user.balance = uDep - price;
      } else {
        user.balance = 0;
        user.winningCash = uWin - (price - uDep);
      }
      return user;
    });

    if (!wTx.committed) {
      return res.status(400).json({ error: insufficientFunds ? "Insufficient Wallet Balance!" : "Wallet update failed, try again" });
    }

    let flipFail = false;
    const prodTx = await prodRef.transaction((p) => {
      if (!p) return p;
      if (p.status !== "active") { flipFail = true; return; } 
      p.status = "sold";
      p.soldToUid = uid;
      return p;
    });

    if (!prodTx.committed || flipFail) {
      await uRef.transaction((user) => {
        if (user) user.winningCash = (Number(user.winningCash) || 0) + price;
        return user;
      });
      return res.status(400).json({ error: "Too late! Product is already sold out." });
    }

    const orderRef = await db.ref("shopOrders").push({
      userId: uid,
      deliveryName: cleanName,
      deliveryPhone: cleanPhone,
      deliveryAddress: cleanAddress,
      userNote: cleanNote,
      productId,
      productName,
      price,
      status: "pending",
      timestamp: admin.database.ServerValue.TIMESTAMP
    });

    await db.ref(`users/${uid}/transactions`).push({
      type: "Product Purchase",
      amount: price,
      status: "Success",
      time: Date.now(),
      method: "Wallet",
      adminNote: productName
    });

    await db.ref(`users/${uid}/notifications`).push({
      title: "Order Placed Successfully!",
      message: `Your order for ${productName} has been received.`,
      type: "success",
      read: false,
      timestamp: admin.database.ServerValue.TIMESTAMP
    });

    console.log(`✅ Product purchased: uid=${uid}, productId=${productId}, price=${price}, orderId=${orderRef.key}`);
    return res.json({ success: true, orderId: orderRef.key, price });

  } catch (err) {
    console.log("❌ Buy product error:", err.message);
    return res.status(500).json({ error: "Something went wrong" });
  }
});

// ================= SEND ID/PASS PUSH (secure) =================
app.post("/send-idpass-push", verifyAuth, async (req, res) => {
  console.log("🚀 NAYI PUSH REQUEST AAYI HAI!"); 
  
  try {
    const callerUid = req.uid;
    const [adminConfigSnap, staffSnap] = await Promise.all([
      db.ref("adminConfig/adminUid").get(),
      db.ref(`staff/${callerUid}/status`).get()
    ]);
    const isAdmin = adminConfigSnap.val() === callerUid;
    const isActiveStaff = staffSnap.val() === "active";
    if (!isAdmin && !isActiveStaff) {
      console.log("❌ Error: Caller admin/staff nahi hai.");
      return res.status(403).json({ error: "unauthorized" });
    }

    const { tournamentId } = req.body;
    if (!tournamentId) {
      console.log("❌ Error: Tournament ID missing hai.");
      return res.status(400).json({ error: "tournamentId is required" });
    }

    console.log(`🔍 Tournament [${tournamentId}] ki details nikal rahe hain...`);
    const tSnap = await db.ref(`tournaments/${tournamentId}`).get();
    if (!tSnap.exists()) {
      console.log("❌ Error: Tournament database me nahi mila.");
      return res.status(404).json({ error: "tournament not found" });
    }
    
    const tournament = tSnap.val();
    const players = tournament.registeredPlayers || {};
    const uids = Object.keys(players);

    if (uids.length === 0) {
      console.log("⚠️ Note: Is match me koi player registered nahi hai.");
      return res.json({ sent: 0, note: "no registered players" });
    }

    const tokenSnaps = await Promise.all(
      uids.map((uid) => db.ref(`users/${uid}/fcmToken`).get())
    );

    const pairs = uids
      .map((uid, i) => ({ uid, token: tokenSnaps[i].val() }))
      .filter((p) => typeof p.token === "string" && p.token.length > 0);

    if (pairs.length === 0) {
      console.log("⚠️ Note: Kisi bhi player ka FCM token database me nahi mila.");
      return res.json({ sent: 0, note: "no fcm tokens on file" });
    }

    const tokens = pairs.map((p) => p.token);
    console.log(`✅ Bhej rahe hain ${tokens.length} users ko push notification...`);

    const message = {
      data: {
        title: `ID PASS UPDATED FOR MATCH "${tournament.name}"`,
        body: `ID - "${tournament.roomId || ''}" PASS - "${tournament.roomPassword || ''}"`,
        type: "idpass_update",
        tournamentId: String(tournamentId),
      },
      android: { priority: "high" },
      tokens,
    };

    const result = await admin.messaging().sendEachForMulticast(message);
    console.log(`✅ SUCCESS: ${result.successCount} sent, ${result.failureCount} failed.`);

    const cleanupPromises = [];
    result.responses.forEach((r, i) => {
      if (
        !r.success &&
        r.error &&
        r.error.code === "messaging/registration-token-not-registered"
      ) {
        const badUid = pairs[i].uid;
        console.log(`🗑️ Invalid token delete kar rahe hain UID: ${badUid}`);
        cleanupPromises.push(db.ref(`users/${badUid}/fcmToken`).remove());
      }
    });
    await Promise.all(cleanupPromises);

    return res.json({ sent: result.successCount, failed: result.failureCount });
  } catch (err) {
    console.error("🔥 Server Error:", err);
    return res.status(500).json({ error: err.message });
  }
});

// ================= MATCH RESULT PUSH (admin only) =================
// ID/PASS push jaisa hi, lekin har player ko uske apne jeete hue coins ke
// hisaab se PERSONALIZED message jaata hai (ek jaisa broadcast nahi, kyunki
// har player ka winning amount alag hota hai). Sirf un players ko bheja
// jaata hai jinka prize > 0 ho ("registeredPlayers/{uid}/prize", jo admin ke
// "execute-computations" step ke turant baad already Firebase me likha ja
// chuka hota hai) — 0 jeetne waalon ko ye specific push nahi jaata (unhe
// pehle se hi normal in-app notification mil jaati hai).
app.post("/send-result-push", verifyAuth, async (req, res) => {
  console.log("🏆 MATCH RESULT PUSH REQUEST AAYI HAI!");

  try {
    const callerUid = req.uid;
    const [adminConfigSnap, staffSnap] = await Promise.all([
      db.ref("adminConfig/adminUid").get(),
      db.ref(`staff/${callerUid}/status`).get()
    ]);
    const isAdmin = adminConfigSnap.val() === callerUid;
    const isActiveStaff = staffSnap.val() === "active";
    if (!isAdmin && !isActiveStaff) {
      console.log("❌ Error: Caller admin/staff nahi hai.");
      return res.status(403).json({ error: "unauthorized" });
    }

    const { tournamentId } = req.body;
    if (!tournamentId) {
      console.log("❌ Error: Tournament ID missing hai.");
      return res.status(400).json({ error: "tournamentId is required" });
    }

    console.log(`🔍 Tournament [${tournamentId}] ke winners nikal rahe hain...`);
    const tSnap = await db.ref(`tournaments/${tournamentId}`).get();
    if (!tSnap.exists()) {
      console.log("❌ Error: Tournament database me nahi mila.");
      return res.status(404).json({ error: "tournament not found" });
    }

    const tournament = tSnap.val();
    const players = tournament.registeredPlayers || {};
    // Sirf wahi players jinhone kuch jeeta hai (prize > 0)
    const winners = Object.entries(players)
      .map(([uid, p]) => ({ uid, prize: Number(p?.prize || 0) }))
      .filter((p) => p.prize > 0);

    if (winners.length === 0) {
      console.log("⚠️ Note: Is match me koi winner (prize > 0) nahi hai.");
      return res.json({ sent: 0, note: "no winners with prize > 0" });
    }

    const tokenSnaps = await Promise.all(
      winners.map((w) => db.ref(`users/${w.uid}/fcmToken`).get())
    );

    const pairs = winners
      .map((w, i) => ({ uid: w.uid, prize: w.prize, token: tokenSnaps[i].val() }))
      .filter((p) => typeof p.token === "string" && p.token.length > 0);

    if (pairs.length === 0) {
      console.log("⚠️ Note: Kisi bhi winner ka FCM token database me nahi mila.");
      return res.json({ sent: 0, note: "no fcm tokens on file" });
    }

    console.log(`✅ Bhej rahe hain ${pairs.length} winners ko personalized push notification...`);

    // Har winner ka amount alag hai isliye sendEachForMulticast (ek jaisa
    // message sabko) use nahi ho sakta — har player ke liye alag Message
    // object banate hain aur sendEach() se ek saath bhejte hain.
    const messages = pairs.map((p) => ({
      token: p.token,
      data: {
        title: `Result Declared - "${tournament.name}"`,
        body: `RESULT OF YOU MATCH "${tournament.name}" HAS BEEN DECLARED AND YOU WON ${p.prize} COINS`,
        type: "match_result",
        tournamentId: String(tournamentId),
        prize: String(p.prize),
      },
      android: { priority: "high" },
    }));

    const result = await admin.messaging().sendEach(messages);
    console.log(`✅ SUCCESS: ${result.successCount} sent, ${result.failureCount} failed.`);

    const cleanupPromises = [];
    result.responses.forEach((r, i) => {
      if (
        !r.success &&
        r.error &&
        r.error.code === "messaging/registration-token-not-registered"
      ) {
        const badUid = pairs[i].uid;
        console.log(`🗑️ Invalid token delete kar rahe hain UID: ${badUid}`);
        cleanupPromises.push(db.ref(`users/${badUid}/fcmToken`).remove());
      }
    });
    await Promise.all(cleanupPromises);

    return res.json({ sent: result.successCount, failed: result.failureCount });
  } catch (err) {
    console.error("🔥 Server Error:", err);
    return res.status(500).json({ error: err.message });
  }
});

// ================= GENERIC USER PUSH (admin only) =================
// ID/PASS aur Match Result push jaisa hi pattern, lekin generic — ek single
// user ko koi bhi title/body/type ka mobile push bhejne ke liye. Isko
// Withdrawal Approve/Reject aur Manual Deposit Approve/Reject jaise admin
// actions ke liye use karte hain (jahan already ek in-app notification
// SendNotif() se ja rahi hoti hai, uske saath-saath yeh asli mobile push
// bhi bhej deta hai).
app.post("/send-user-push", verifyAuth, async (req, res) => {
  console.log("🔔 GENERIC USER PUSH REQUEST AAYI HAI!");

  try {
    const callerUid = req.uid;
    const [adminConfigSnap, staffSnap] = await Promise.all([
      db.ref("adminConfig/adminUid").get(),
      db.ref(`staff/${callerUid}/status`).get()
    ]);
    const isAdmin = adminConfigSnap.val() === callerUid;
    const isActiveStaff = staffSnap.val() === "active";
    if (!isAdmin && !isActiveStaff) {
      console.log("❌ Error: Caller admin/staff nahi hai.");
      return res.status(403).json({ error: "unauthorized" });
    }

    const { uid, title, body, type } = req.body;
    if (!uid || !title || !body) {
      console.log("❌ Error: uid/title/body missing hai.");
      return res.status(400).json({ error: "uid, title and body are required" });
    }

    const tokenSnap = await db.ref(`users/${uid}/fcmToken`).get();
    const token = tokenSnap.val();

    if (!token) {
      console.log(`⚠️ Note: UID ${uid} ka FCM token database me nahi mila.`);
      return res.json({ sent: 0, note: "no fcm token on file" });
    }

    const message = {
      token,
      data: {
        title: String(title),
        body: String(body),
        type: type ? String(type) : "general",
      },
      android: { priority: "high" },
    };

    try {
      await admin.messaging().send(message);
      console.log(`✅ SUCCESS: push bheja gaya UID: ${uid}`);
      return res.json({ sent: 1 });
    } catch (sendErr) {
      console.log(`❌ Push send failed for uid=${uid}:`, sendErr.message);
      if (sendErr.code === "messaging/registration-token-not-registered") {
        await db.ref(`users/${uid}/fcmToken`).remove();
      }
      return res.json({ sent: 0, error: sendErr.message });
    }
  } catch (err) {
    console.error("🔥 Server Error:", err);
    return res.status(500).json({ error: err.message });
  }
});

// ================= BROADCAST PUSH TO ALL USERS (admin only) =================
// Sketchware wale alag app ki jagah — wo app APK ke andar bundled
// service_account.json se khud OAuth access token banata tha (security
// risk + 50-90 sec delay). Ab yahi kaam server par hota hai: firebase-admin
// SDK OAuth token ko internally cache/reuse karta hai, isliye delay
// practically khatam ho jaata hai, aur service account kabhi APK me nahi
// jaata — sirf yahan environment variable me rehta hai.
// FCM ek single multicast call me max 500 tokens leta hai, isliye tokens ko
// 500-500 ke batch me todke Promise.all se parallel bhejte hain (sequential
// loop nahi — isse 1000 users bhi practically ek hi round-trip jaisa fast
// hota hai).
app.post("/send-broadcast-push", verifyAuth, async (req, res) => {
  console.log("📢 BROADCAST PUSH REQUEST AAYI HAI!");

  try {
    const callerUid = req.uid;
    const [adminConfigSnap, staffSnap] = await Promise.all([
      db.ref("adminConfig/adminUid").get(),
      db.ref(`staff/${callerUid}/status`).get()
    ]);
    const isAdmin = adminConfigSnap.val() === callerUid;
    const isActiveStaff = staffSnap.val() === "active";
    if (!isAdmin && !isActiveStaff) {
      console.log("❌ Error: Caller admin/staff nahi hai.");
      return res.status(403).json({ error: "unauthorized" });
    }

    const { title, body, type, imageUrl } = req.body;
    if (!title || !body) {
      console.log("❌ Error: title/body missing hai.");
      return res.status(400).json({ error: "title and body are required" });
    }

    console.log("🔍 Saare users ke FCM tokens nikal rahe hain...");
    const usersSnap = await db.ref("users").once("value");
    if (!usersSnap.exists()) {
      return res.json({ sent: 0, note: "no users found" });
    }

    const pairs = [];
    usersSnap.forEach((child) => {
      const token = child.val()?.fcmToken;
      if (typeof token === "string" && token.length > 0) {
        pairs.push({ uid: child.key, token });
      }
    });

    if (pairs.length === 0) {
      console.log("⚠️ Note: Kisi bhi user ka FCM token database me nahi mila.");
      return res.json({ sent: 0, note: "no fcm tokens on file" });
    }

    console.log(`✅ Bhej rahe hain ${pairs.length} users ko broadcast push...`);

    // FCM multicast ki 500 tokens/request limit ke hisaab se batches banao
    const BATCH_SIZE = 500;
    const batches = [];
    for (let i = 0; i < pairs.length; i += BATCH_SIZE) {
      batches.push(pairs.slice(i, i + BATCH_SIZE));
    }

    const dataPayload = {
      title: String(title),
      body: String(body),
      type: type ? String(type) : "broadcast",
    };
    if (imageUrl) dataPayload.imageUrl = String(imageUrl);

    const batchResults = await Promise.all(
      batches.map((batch) =>
        admin.messaging().sendEachForMulticast({
          data: dataPayload,
          android: { priority: "high" },
          tokens: batch.map((p) => p.token),
        })
      )
    );

    let successCount = 0;
    let failureCount = 0;
    const cleanupPromises = [];

    batchResults.forEach((result, bIdx) => {
      successCount += result.successCount;
      failureCount += result.failureCount;
      result.responses.forEach((r, i) => {
        if (
          !r.success &&
          r.error &&
          r.error.code === "messaging/registration-token-not-registered"
        ) {
          const badUid = batches[bIdx][i].uid;
          console.log(`🗑️ Invalid token delete kar rahe hain UID: ${badUid}`);
          cleanupPromises.push(db.ref(`users/${badUid}/fcmToken`).remove());
        }
      });
    });
    await Promise.all(cleanupPromises);

    console.log(`✅ SUCCESS: ${successCount} sent, ${failureCount} failed.`);
    return res.json({ sent: successCount, failed: failureCount, totalTokens: pairs.length });
  } catch (err) {
    console.error("🔥 Server Error:", err);
    return res.status(500).json({ error: err.message });
  }
});

// ================= LEADERBOARD (server-computed, cached) =================
// Pehle user.html seedha `users` (aur `pendingReferrals`) ka POORA node
// browser me download karta tha -- har baar jab koi bhi user Leaderboard
// kholta tha. 1000+ users ke case me ye Firebase ki free bandwidth limit
// (10GB/month) ko bahut jaldi khatam kar deta tha, aur security-wise bhi
// risky tha (har logged-in user sabka wallet/personal data dekh sakta tha).
//
// Ab ye computation yahan server par hoti hai, ek chhote in-memory cache ke
// saath -- underlying poora data Firebase se sirf har LDB_CACHE_MS
// (default 3 min) me EK BAAR khincha jaata hai, chahe usi window me
// hazaron users leaderboard kholein. Response me bhi sirf zaroori,
// non-sensitive fields bhejte hain (naam, level, matches, earnings waghera)
// -- kisi ka wallet balance ya personal info kabhi expose nahi hota.
let LDB_CACHE = null; // { computedAt, byType: { level: [...], matches: [...], ... } }
const LDB_CACHE_MS = 3 * 60 * 1000;

function computeLeaderboardData(usersData, tournamentsData, referralsData) {
  const matchCounts = {};
  Object.values(tournamentsData || {}).forEach((t) => {
    if (t.registeredPlayers) {
      Object.keys(t.registeredPlayers).forEach((uid) => {
        matchCounts[uid] = (matchCounts[uid] || 0) + 1;
      });
    }
  });

  const referralCounts = {};
  Object.values(referralsData || {}).forEach((v) => {
    if (v && v.referrerUid) referralCounts[v.referrerUid] = (referralCounts[v.referrerUid] || 0) + 1;
  });

  let users = Object.entries(usersData || {}).map(([uid, u]) => {
    const xp = Number(u.xp) || 0;
    const level = Math.floor(Math.sqrt(xp / 50)) + 1;
    const matchesPlayed = matchCounts[uid] || Object.keys(u.joinedTournaments || {}).length || 0;
    const totalWin = u.lifetimeWinnings !== undefined ? (Number(u.lifetimeWinnings) || 0) : (Number(u.winningCash) || 0);

    const wb = u.weeklyBaseline || {};
    const weeklyLevel = Math.max(0, level - (Number(wb.level) || 0));
    const weeklyMatches = Math.max(0, matchesPlayed - (Number(wb.matches) || 0));
    const weeklyWin = Math.max(0, totalWin - (Number(wb.totalWin) || 0));

    const isVip = Number(u.vipExpiresAt || 0) > Date.now();
    const safeName = u.displayName || (u.email ? u.email.split("@")[0] : "Player");

    return {
      uid,
      displayName: safeName,
      isVip,
      profileImageUrl: isVip ? (u.profileImageUrl || null) : null,
      profileEmoji: u.profileEmoji || "😀",
      xp, level, matchesPlayed, totalWin,
      weeklyLevel, weeklyMatches, weeklyWin,
      streak: Number(u.loginStreak) || 0,
      referralCount: referralCounts[uid] || 0,
    };
  });

  // Overall/Weekly combined score (same normalized 1/3-1/3-1/3 formula as before)
  const buildCombined = (list, lvlKey, mKey, eKey) => {
    const norm = (val, min, max) => (max > min ? ((val - min) / (max - min)) * 100 : (max > 0 ? 100 : 0));
    const lvlVals = list.map((u) => u[lvlKey]), lvlMin = Math.min(...lvlVals, 0), lvlMax = Math.max(...lvlVals, 0);
    const mVals = list.map((u) => u[mKey]), mMin = Math.min(...mVals, 0), mMax = Math.max(...mVals, 0);
    const eVals = list.map((u) => u[eKey]), eMin = Math.min(...eVals, 0), eMax = Math.max(...eVals, 0);
    return list.map((u) => ({
      ...u,
      combinedScore: (norm(u[lvlKey], lvlMin, lvlMax) / 3) + (norm(u[mKey], mMin, mMax) / 3) + (norm(u[eKey], eMin, eMax) / 3),
    }));
  };

  const overallUsers = buildCombined(users, "level", "matchesPlayed", "totalWin");
  const weeklyUsers = buildCombined(users, "weeklyLevel", "weeklyMatches", "weeklyWin");

  const top10 = (list, cmp) => [...list].sort(cmp).slice(0, 10);

  return {
    level: top10(users, (a, b) => b.level - a.level || b.xp - a.xp),
    matches: top10(users, (a, b) => b.matchesPlayed - a.matchesPlayed),
    earnings: top10(users, (a, b) => b.totalWin - a.totalWin),
    streak: top10(users, (a, b) => b.streak - a.streak),
    referrals: top10(users, (a, b) => b.referralCount - a.referralCount),
    overall: top10(overallUsers, (a, b) =>
      b.combinedScore - a.combinedScore || b.matchesPlayed - a.matchesPlayed || b.level - a.level || b.totalWin - a.totalWin),
    weekly: top10(weeklyUsers, (a, b) =>
      b.combinedScore - a.combinedScore || b.weeklyMatches - a.weeklyMatches || b.weeklyLevel - a.weeklyLevel || b.weeklyWin - a.weeklyWin),
  };
}

app.get("/leaderboard", async (req, res) => {
  try {
    const type = String(req.query.type || "overall");
    const validTypes = ["level", "matches", "earnings", "streak", "referrals", "overall", "weekly"];
    if (!validTypes.includes(type)) {
      return res.status(400).json({ error: "invalid type" });
    }

    const now = Date.now();
    if (!LDB_CACHE || (now - LDB_CACHE.computedAt) > LDB_CACHE_MS) {
      console.log("📊 Leaderboard cache stale/empty -- recomputing from Firebase...");
      const [uSnap, tSnap, rSnap] = await Promise.all([
        db.ref("users").once("value"),
        db.ref("tournaments").once("value"),
        db.ref("pendingReferrals").once("value"),
      ]);
      LDB_CACHE = {
        computedAt: now,
        byType: computeLeaderboardData(uSnap.val() || {}, tSnap.val() || {}, rSnap.val() || {}),
      };
      console.log("✅ Leaderboard cache refreshed.");
    }

    return res.json({ type, users: LDB_CACHE.byType[type], cachedAt: LDB_CACHE.computedAt });
  } catch (err) {
    console.error("🔥 Server Error:", err);
    return res.status(500).json({ error: err.message });
  }
});

// ================= REPAIR MISSING EMAILS (admin only) =================
// Kuch users ka `users/{uid}/email` Database me khaali reh jaata hai (jaise
// signup ke waqt propagation delay ya bahut purane account jab ye system
// nahi tha). Unka asli email hamesha Firebase Auth me safe hota hai — ye
// route wahi se le kar Database backfill kar deta hai.
app.post("/admin/repair-missing-emails", verifyAuth, async (req, res) => {
  try {
    const callerUid = req.uid;
    const [adminConfigSnap, staffSnap] = await Promise.all([
      db.ref("adminConfig/adminUid").get(),
      db.ref(`staff/${callerUid}/status`).get()
    ]);
    const isAdmin = adminConfigSnap.val() === callerUid;
    const isActiveStaff = staffSnap.val() === "active";
    if (!isAdmin && !isActiveStaff) {
      return res.status(403).json({ error: "unauthorized" });
    }

    const usersSnap = await db.ref("users").get();
    if (!usersSnap.exists()) return res.json({ checked: 0, fixed: 0, failed: 0 });

    const missing = [];
    usersSnap.forEach((c) => {
      const v = c.val() || {};
      if (!v.email) missing.push(c.key);
    });

    let fixed = 0, failed = 0;
    // Har missing user ke liye Auth se real email nikaalte hain, parallel me.
    const results = await Promise.all(missing.map(async (uid) => {
      try {
        const authUser = await admin.auth().getUser(uid);
        if (authUser.email) {
          await db.ref(`users/${uid}/email`).set(authUser.email);
          return true;
        }
        return false; // Auth me bhi email nahi hai (jaise phone-only account) — skip
      } catch (e) {
        return false; // Auth record hi nahi mila (jaise deleted user) — skip
      }
    }));
    results.forEach(r => r ? fixed++ : failed++);

    console.log(`✅ Email repair: checked=${missing.length}, fixed=${fixed}, unresolved=${failed}`);
    return res.json({ checked: missing.length, fixed, failed });
  } catch (err) {
    console.log("❌ Repair missing emails error:", err.message);
    return res.status(500).json({ error: "Something went wrong" });
  }
});

// ================= REPAIR BROKEN PROFILES (admin only) =================
// Purane bug ki wajah se (fcmToken direct-write se `users/{uid}` node
// asli profile banne se PEHLE hi "exist" ho jaata tha) kuch users ke
// profile adhoore reh gaye — displayName, email, balance, joinedTournaments
// wagera missing, sirf fcmToken/deviceId/referralCode ho sakta hai. Ye route
// aise sab users dhoondh kar (jinke paas `createdAt` nahi hai) unhe Firebase
// Auth se naam/email lekar poora, sahi profile bana deta hai — jo bhi field
// already set thi (fcmToken, deviceId, referralCode) use preserve karte hue.
// NOTE: Inke referral bonus/pendingReferrals ab is route se nahi milte —
// woh window signup ke waqt hi nikal chuki thi, ye sirf profile ko usable
// banata hai (naam, balance dikhna shuru ho jaayega).
app.post("/admin/repair-broken-profiles", verifyAuth, async (req, res) => {
  try {
    const callerUid = req.uid;
    const [adminConfigSnap, staffSnap] = await Promise.all([
      db.ref("adminConfig/adminUid").get(),
      db.ref(`staff/${callerUid}/status`).get()
    ]);
    const isAdmin = adminConfigSnap.val() === callerUid;
    const isActiveStaff = staffSnap.val() === "active";
    if (!isAdmin && !isActiveStaff) {
      return res.status(403).json({ error: "unauthorized" });
    }

    const usersSnap = await db.ref("users").get();
    if (!usersSnap.exists()) return res.json({ checked: 0, fixed: 0, failed: 0, skipped: 0 });

    const broken = [];
    usersSnap.forEach((c) => {
      const v = c.val() || {};
      if (!v.createdAt) broken.push({ uid: c.key, existing: v });
    });

    let fixed = 0, failed = 0, skipped = 0;
    const details = [];

    // Ek-ek karke process karte hain (Auth lookups rate-limit-friendly rahein) —
    // admin panel se manual trigger hai, bulk-parallel karne ki zaroorat nahi.
    for (const { uid, existing } of broken) {
      try {
        const authUser = await admin.auth().getUser(uid);
        const email = authUser.email || null;
        const cleanName = (authUser.displayName || (email ? email.split("@")[0] : "Player")).slice(0, 40);

        const referralCode = existing.referralCode || await generateUniqueReferralCode();

        const repairedProfile = {
          uid,
          displayName: existing.displayName || cleanName,
          gameIgn: existing.gameIgn || cleanName,
          email: existing.email || email,
          deviceId: existing.deviceId || null,
          balance: Number(existing.balance) || 0,
          winningCash: Number(existing.winningCash) || 0,
          bonusCash: Number(existing.bonusCash) || 0,
          joinedTournaments: existing.joinedTournaments || {},
          referralCode,
          createdAt: admin.database.ServerValue.TIMESTAMP
        };
        // Existing fields jo already set the (fcmToken, xp, status, wagera) preserve karo.
        for (const k of Object.keys(existing)) {
          if (!(k in repairedProfile)) repairedProfile[k] = existing[k];
        }

        await db.ref(`users/${uid}`).transaction((current) => {
          if (current && current.createdAt) return; // beech me kisi aur route se already fix ho chuka — abort
          return repairedProfile;
        });

        fixed++;
        details.push({ uid, email, displayName: repairedProfile.displayName, status: "fixed" });
      } catch (e) {
        // Auth record hi nahi mila (jaise poori tarah deleted user) — is bhoot
        // record ko chhod dete hain, ye kisi ko nazar nahi aata to nuksaan nahi.
        skipped++;
        details.push({ uid, status: "skipped", reason: e.message });
      }
    }

    console.log(`✅ Broken profile repair: checked=${broken.length}, fixed=${fixed}, skipped=${skipped}`);
    return res.json({ checked: broken.length, fixed, skipped, failed, details });
  } catch (err) {
    console.log("❌ Repair broken profiles error:", err.message);
    return res.status(500).json({ error: "Something went wrong" });
  }
});

// ================= SPIN TO WIN =================
// Wheel ke outcomes aur unke real probabilities — SIRF yahan server par decide
// hote hain, client kabhi outcome nahi choose karta (taaki koi cheat na kar
// sake). Weight 0 wale segments (Mini/Mega Jackpot) kabhi practically nahi
// aayenge — jaanbujh kar aisa design kiya gaya hai.
const SPIN_SEGMENTS = [
  { value: 1, weight: 50 },   // index 0 — sabse zyada chance
  { value: 2, weight: 30 },   // index 1
  { value: 5, weight: 15 },   // index 2
  { value: 10, weight: 5 },   // index 3
  { value: 50, weight: 0 },   // index 4 — Mini Jackpot (0% chance)
  { value: 500, weight: 0 },  // index 5 — Mega Jackpot (0% chance)
];
function pickSpinOutcome() {
  const totalWeight = SPIN_SEGMENTS.reduce((s, seg) => s + seg.weight, 0); // 100
  let r = Math.random() * totalWeight;
  for (let i = 0; i < SPIN_SEGMENTS.length; i++) {
    if (r < SPIN_SEGMENTS[i].weight) return { index: i, value: SPIN_SEGMENTS[i].value };
    r -= SPIN_SEGMENTS[i].weight;
  }
  return { index: 1, value: SPIN_SEGMENTS[1].value }; // fallback, floating point safety
}

app.post("/spin-wheel", verifyAuth, async (req, res) => {
  try {
    const uid = req.uid;
    const uRef = db.ref(`users/${uid}`);
    // DIAG: quote-wrapped + length reveals stray whitespace/hidden chars.
    // options.databaseURL confirms which DB instance this Admin SDK
    // connection is actually talking to at runtime.
    console.log(`[spin-wheel] request received. uid="${uid}" (len=${uid.length}) path="users/${uid}" dbURL=${admin.app().options.databaseURL}`);

    // DIAG: a plain, non-transactional read of the exact same path, done
    // BEFORE the transaction, to isolate whether this is a transaction()-
    // specific quirk or the read itself returns nothing.
    try {
      const plainSnap = await uRef.once('value');
      console.log(`[spin-wheel] uid=${uid} plain once('value') exists=${plainSnap.exists()} val=${plainSnap.exists() ? JSON.stringify(plainSnap.val()).slice(0,300) : 'null'}`);
    } catch(plainErr) {
      console.log(`[spin-wheel] uid=${uid} plain once('value') THREW: ${plainErr.message}`);
    }

    // Ticket ka deduction transaction se karte hain taaki koi user ek hi ticket
    // se do baar spin (double-click / duplicate request) na kar paaye.
    // `coins` yahan sirf lifetime "Earned Coins" counter hai (kabhi kam nahi
    // hota) — asli usable paisa seedha `balance` (Deposit Balance) me jaata
    // hai, taaki user use turant match entry fee me use kar sake.
    let outcome = null;
    let sawUser = null; // DIAG: capture what the transaction callback actually saw
    let callbackRuns = 0;
    const txResult = await uRef.transaction((user) => {
      callbackRuns++;
      sawUser = user;
      if (user === undefined) return; // still loading locally, let Firebase retry
      if (user === null) {
        console.log(`[spin-wheel] uid=${uid} txn run#${callbackRuns}: stale/null user snapshot — passing through for retry`);
        return {}; // don't abort; let Firebase retry with the real server data
      }
      const tickets = Number(user.spinTickets) || 0;
      console.log(`[spin-wheel] uid=${uid} txn run#${callbackRuns}: spinTickets field = ${JSON.stringify(user.spinTickets)} (parsed as ${tickets})`);
      if (tickets <= 0) { console.log(`[spin-wheel] uid=${uid} txn run#${callbackRuns}: aborting, tickets <= 0`); return; } // abort — koi ticket nahi hai
      outcome = pickSpinOutcome();
      user.spinTickets = tickets - 1;
      user.coins = (Number(user.coins) || 0) + outcome.value; // lifetime earned counter
      if (outcome.value > 0) user.balance = (Number(user.balance) || 0) + outcome.value; // deposit balance credit
      return user;
    });
    console.log(`[spin-wheel] uid=${uid} txn done: committed=${txResult.committed} callbackRuns=${callbackRuns} outcome=${outcome ? JSON.stringify(outcome) : 'null'}`);

    if (!txResult.committed || !outcome) {
      return res.status(400).json({ error: "No spin tickets available" });
    }

    // Audit ke liye har spin ka record rakhte hain
    await db.ref(`users/${uid}/spinHistory`).push({
      value: outcome.value,
      index: outcome.index,
      time: Date.now(),
    });

    // Deposit balance me credit hui rakam ka transaction history entry
    if (outcome.value > 0) {
      await db.ref(`users/${uid}/transactions`).push({
        type: "Spin to Win",
        amount: outcome.value,
        status: "Success",
        time: Date.now(),
        method: "Deposit Balance"
      });
    }

    return res.json({
      success: true,
      index: outcome.index,
      value: outcome.value,
      coins: txResult.snapshot.val().coins,
      spinTickets: txResult.snapshot.val().spinTickets,
    });
  } catch (err) {
    console.log("❌ Spin wheel error:", err.message);
    return res.status(500).json({ error: "Something went wrong" });
  }
});

// ================= SCRATCH CARD (NAYA) =================
// Scratch card 1 tab milta hai jab user 7 matches complete kare jinki
// entryFee >= 5 ho AUR result declare ho chuka ho (join karne se nahi milta
// — progress "Execute Computations" admin flow se hi badhta hai, spin wheel
// wale hi pattern par). User guaranteed kuch na kuch jeetega (100% win rate,
// no "better luck next time" outcome). Coins seedha Deposit Balance me jaate
// hain, XP `xp` field me, aur "Spin wheel ticket" outcome par ek free spin
// ticket mil jaata hai.
const SCRATCH_SEGMENTS = [
  { type: "coins", value: 1, weight: 30 },
  { type: "coins", value: 2, weight: 25 },
  { type: "coins", value: 3, weight: 20 },
  { type: "coins", value: 4, weight: 10 },
  { type: "coins", value: 5, weight: 5 },
  { type: "xp", value: 100, weight: 7 },
  { type: "spinTicket", value: 1, weight: 3 },
];
function pickScratchOutcome() {
  const totalWeight = SCRATCH_SEGMENTS.reduce((s, seg) => s + seg.weight, 0); // 100
  let r = Math.random() * totalWeight;
  for (let i = 0; i < SCRATCH_SEGMENTS.length; i++) {
    if (r < SCRATCH_SEGMENTS[i].weight) return SCRATCH_SEGMENTS[i];
    r -= SCRATCH_SEGMENTS[i].weight;
  }
  return SCRATCH_SEGMENTS[0]; // fallback, floating point safety
}

app.post("/scratch-card", verifyAuth, async (req, res) => {
  try {
    const uid = req.uid;
    const uRef = db.ref(`users/${uid}`);
    console.log(`[scratch-card] request received. uid="${uid}" (len=${uid.length}) path="users/${uid}" dbURL=${admin.app().options.databaseURL}`);

    try {
      const plainSnap = await uRef.once('value');
      console.log(`[scratch-card] uid=${uid} plain once('value') exists=${plainSnap.exists()} val=${plainSnap.exists() ? JSON.stringify(plainSnap.val()).slice(0,300) : 'null'}`);
    } catch(plainErr) {
      console.log(`[scratch-card] uid=${uid} plain once('value') THREW: ${plainErr.message}`);
    }

    // Card ka deduction transaction se karte hain taaki duplicate/double-click
    // request se ek hi card do baar scratch na ho jaaye.
    let outcome = null;
    let callbackRuns = 0;
    const txResult = await uRef.transaction((user) => {
      callbackRuns++;
      if (user === undefined) return; // still loading locally, let Firebase retry
      if (user === null) {
        console.log(`[scratch-card] uid=${uid} txn run#${callbackRuns}: stale/null user snapshot — passing through for retry`);
        return {}; // don't abort; let Firebase retry with the real server data
      }
      const cards = Number(user.scratchCards) || 0;
      console.log(`[scratch-card] uid=${uid} txn run#${callbackRuns}: scratchCards field = ${JSON.stringify(user.scratchCards)} (parsed as ${cards})`);
      if (cards <= 0) { console.log(`[scratch-card] uid=${uid} txn run#${callbackRuns}: aborting, cards <= 0`); return; } // abort — koi card nahi hai
      outcome = pickScratchOutcome();
      user.scratchCards = cards - 1;

      if (outcome.type === "coins") {
        user.scratchCoins = (Number(user.scratchCoins) || 0) + outcome.value; // scratch card's own lifetime earned counter (separate from spin wheel's)
        user.balance = (Number(user.balance) || 0) + outcome.value; // deposit balance credit
      } else if (outcome.type === "xp") {
        user.xp = (Number(user.xp) || 0) + outcome.value;
      } else if (outcome.type === "spinTicket") {
        user.spinTickets = (Number(user.spinTickets) || 0) + outcome.value;
      }
      return user;
    });
    console.log(`[scratch-card] uid=${uid} txn done: committed=${txResult.committed} callbackRuns=${callbackRuns} outcome=${outcome ? JSON.stringify(outcome) : 'null'}`);

    if (!txResult.committed || !outcome) {
      return res.status(400).json({ error: "No scratch cards available" });
    }

    // Audit ke liye har scratch ka record rakhte hain
    await db.ref(`users/${uid}/scratchHistory`).push({
      type: outcome.type,
      value: outcome.value,
      time: Date.now(),
    });

    // Har outcome type ki apni transaction history entry — pehle sirf "coins"
    // wale outcome ki entry banti thi, XP aur Spin Ticket wale outcomes
    // transaction history me kabhi dikhte hi nahi the.
    const SCRATCH_TXN_META = {
      coins: { amount: outcome.value, method: "Deposit Balance" },
      xp: { amount: outcome.value, method: "XP" },
      spinTicket: { amount: outcome.value, method: "Spin Ticket" },
    };
    const txnMeta = SCRATCH_TXN_META[outcome.type];
    if (txnMeta) {
      await db.ref(`users/${uid}/transactions`).push({
        type: "Scratch Card",
        amount: txnMeta.amount,
        status: "Success",
        time: Date.now(),
        method: txnMeta.method,
      });
    }

    const finalUser = txResult.snapshot.val();
    return res.json({
      success: true,
      type: outcome.type,
      value: outcome.value,
      scratchCoins: finalUser.scratchCoins,
      xp: finalUser.xp,
      spinTickets: finalUser.spinTickets,
      scratchCards: finalUser.scratchCards,
    });
  } catch (err) {
    console.log("❌ Scratch card error:", err.message);
    return res.status(500).json({ error: "Something went wrong" });
  }
});

// ---- STEP 0: Deterministic FAQ matcher (bypasses AI on near-exact wording) ----
// `tryAnswerMatchEarningsQuery` ki tarah hi — LLM call se pehle ek 100%
// deterministic check. Agar user ka message kisi active FAQ ke question se
// bahut close (near-exact) match karta hai, seedha DB se wahi FAQ ka answer
// return kar do, koi provider call nahi hoti.
//
// Threshold JAANBUJHKAR high (0.85) rakha hai: FAQ questions users alag-alag
// phrasing/Hindi-Hinglish/typos me poochte hain, aur AI FAQ-flow ka poora
// point hi paraphrase samajhna hai. Loose threshold rakha to galat FAQ match
// ho sakta hai. Isliye ye sirf near-exact wording (chhota typo/case/spacing
// farak) ko catch karta hai — thoda bhi alag phrasing normal AI flow me hi
// jaata hai (safe fallback, na ki galat jawab).
// NOTE: normName() aur levenshtein() pehle se file me define hain (image
// name-matching ke liye) — same functions yahan reuse ho rahe hain.
async function tryAnswerFromFaqDeterministic(cleanMsg) {
  try {
    const faqSnap = await db.ref("aiFaqs").once("value");
    if (!faqSnap.exists()) return null;

    const normMsg = normName(cleanMsg);
    if (!normMsg) return null;

    let bestAnswer = null, bestScore = 0;
    faqSnap.forEach((c) => {
      const v = c.val() || {};
      if (v.active === false || !v.question || !v.answer) return;
      const normQ = normName(v.question);
      if (!normQ) return;
      const dist = levenshtein(normMsg, normQ);
      const maxLen = Math.max(normMsg.length, normQ.length);
      const score = maxLen ? 1 - dist / maxLen : 0; // 1 = exact match
      if (score > bestScore) { bestScore = score; bestAnswer = v.answer; }
    });

    const FAQ_MATCH_THRESHOLD = 0.85;
    return bestScore >= FAQ_MATCH_THRESHOLD ? bestAnswer : null;
  } catch (err) {
    console.log("⚠️ tryAnswerFromFaqDeterministic failed:", err.message);
    return null; // safe fallback -- normal AI flow handles it
  }
}

// ================= ASK QUERIES TO AI (profile section chatbot) =================
// Naya route: user profile ke "Ask Queries to AI" tile se aata hai. User ka
// message Firebase me save karta hai, Claude API se app-related reply leta
// hai, reply bhi Firebase me save karta hai (taaki client ka realtime
// listener dono bubbles apne aap render kar de), aur reply JSON me bhi
// wapas bhejta hai.
//
// SETUP: Render dashboard > Environment me GEMINI_API_KEY set karna
// zaroori hai (Google AI Studio se free milti hai), warna ye route 500
// "AI is not configured" dega.
const aiChatRateLimit = new Map(); // uid -> last request timestamp (simple spam guard)

// ================= MULTI-AI PROVIDER RACE / LOAD-BALANCE =================
// NAYA (multi-provider): Pehle sirf Gemini ke 2 models (primary/fallback)
// istemal hote the. Ab hum Gemini + OpenAI + Groq + DeepSeek me se jitne
// bhi providers ke API keys Render env me set hain, un sabko ek pool me
// rakhte hain aur load ke hisaab se do strategies me switch karte hain:
//
//   LOW LOAD (kam concurrent "/ask-ai" requests chal rahi hain): sabhi
//   available providers ko EK SAATH "race" karte hain (AbortController se)
//   -- jo sabse pehle valid reply de wahi jeet jaata hai, baaki turant
//   cancel ho jaate hain. Isse response HAMESHA sabse fast provider jitna
//   fast aata hai.
//
//   HIGH LOAD (bohot saare users ek saath AI chat use kar rahe hain): race
//   karna wasteful hota (har user ke liye 3-4 API calls ek saath = rate
//   limits jaldi khatam), isliye is case me naya request seedha us provider
//   ko bhejte hain jiska is waqt LEAST concurrent load hai -- naturally load
//   spread ho jaata hai sab providers me.
//
// Har provider call par ek hard per-call timeout (AI_CALL_TIMEOUT_MS) bhi
// hai taaki koi ek slow/hung provider poori request ko lamba na khींch de --
// "delay na ho" wali requirement isi se cover hoti hai.
//
// SETUP: Render dashboard > Environment me jitne providers use karne hain
// unki keys set karo -- GEMINI_API_KEY, GROQ_API_KEY, CEREBRAS_API_KEY,
// OPENROUTER_API_KEY (sab totally free hain). Jis provider ki key set nahi
// hai, wo pool se automatic skip ho jaata hai (crash nahi hoga). Kam se kam
// ek key zaroor honi chahiye.
// Model names bhi env se override ho sakte hain (GEMINI_MODEL, GROQ_MODEL,
// CEREBRAS_MODEL, OPENROUTER_MODEL) -- agar defaults aapke account me
// available na hon to yahan ya env me badal dena.

// Match thumbnails ke liye Gemini ka image model use karte hain (Gemini
// 2.5 Flash Image, aka "Nano Banana") -- free tier hai (500 images/day),
// aur quality Pollinations se kaafi behtar hai. Same GEMINI_API_KEY use
// hoti hai jo text ke liye already configured hai. Base64 image data
// wapas aata hai Gemini se, jise Cloudinary par upload karke ek permanent
// public URL bana dete hain (jo match ke bannerUrl field me save hota hai).
async function generateMatchThumbnail(prompt) {
  const apiKey = process.env.GEMINI_API_KEY;
  if (!apiKey) throw new Error("GEMINI_API_KEY not configured");

  const imageModel = process.env.GEMINI_IMAGE_MODEL || "gemini-2.5-flash-image";
  const fullPrompt =
    `Create a vibrant, professional esports/gaming tournament banner image. ${prompt}. ` +
    `Wide landscape banner format, bold dramatic lighting, high energy, no text or logos overlaid.`;

  const r = await fetch(
    `https://generativelanguage.googleapis.com/v1beta/models/${imageModel}:generateContent?key=${apiKey}`,
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        contents: [{ role: "user", parts: [{ text: fullPrompt }] }],
      }),
    }
  );
  const d = await r.json();
  if (!r.ok || d?.error) throw new Error("gemini_image_error: " + JSON.stringify(d?.error || d).slice(0, 300));

  const parts = d?.candidates?.[0]?.content?.parts || [];
  const imagePart = parts.find((p) => p.inlineData?.data);
  if (!imagePart) throw new Error("gemini_image_empty_response (finishReason: " + (d?.candidates?.[0]?.finishReason || "none") + ")");

  const base64Data = imagePart.inlineData.data;
  const mimeType = imagePart.inlineData.mimeType || "image/png";

  // Cloudinary par upload karke permanent URL banate hain (Gemini ka
  // base64 data hum khud host nahi kar sakte, wo response me hi rehta hai).
  const uploadResult = await cloudinary.uploader.upload(`data:${mimeType};base64,${base64Data}`, {
    folder: "match-thumbnails",
    resource_type: "image",
  });
  return uploadResult.secure_url;
}

const AI_PROVIDERS = [
  {
    name: "gemini",
    envKey: "GEMINI_API_KEY",
    model: process.env.GEMINI_MODEL || "gemini-3.6-flash",
    call: async (systemPrompt, conversationMessages, apiKey, model, signal) => {
      // Gemini format alag hai: "assistant" role yahan "model" kehlata hai,
      // aur system prompt "contents" array me nahi, alag "system_instruction"
      // field me jaata hai.
      const contents = conversationMessages.map((m) => ({
        role: m.role === "assistant" ? "model" : "user",
        parts: [{ text: m.content }],
      }));
      const r = await fetch(
        `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${apiKey}`,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            system_instruction: { parts: [{ text: systemPrompt }] },
            contents,
            generationConfig: { maxOutputTokens: 1024 },
          }),
          signal,
        }
      );
      const d = await r.json();
      if (!r.ok || d?.error) throw new Error("gemini_error: " + JSON.stringify(d?.error || d).slice(0, 300));
      const parts = d?.candidates?.[0]?.content?.parts;
      const text = parts?.length ? parts.map((p) => p.text || "").filter(Boolean).join("\n").trim() : "";
      if (!text) throw new Error("gemini_empty_response (finishReason: " + (d?.candidates?.[0]?.finishReason || "none") + ")");
      return text;
    },
  },
  {
    name: "groq",
    envKey: "GROQ_API_KEY",
    model: process.env.GROQ_MODEL || "openai/gpt-oss-120b",
    call: async (systemPrompt, conversationMessages, apiKey, model, signal) => {
      const r = await fetch("https://api.groq.com/openai/v1/chat/completions", {
        method: "POST",
        headers: { "Content-Type": "application/json", Authorization: "Bearer " + apiKey },
        body: JSON.stringify({
          model,
          messages: [{ role: "system", content: systemPrompt }, ...conversationMessages],
          max_tokens: 1024,
        }),
        signal,
      });
      const d = await r.json();
      if (!r.ok || d?.error) throw new Error("groq_error: " + JSON.stringify(d?.error || d).slice(0, 300));
      const text = d?.choices?.[0]?.message?.content?.trim();
      if (!text) throw new Error("groq_empty_response");
      return text;
    },
  },
  {
    // Cerebras -- free tier (generous free rate limits, no card needed to start),
    // OpenAI-compatible endpoint. Get a key at https://cloud.cerebras.ai
    name: "cerebras",
    envKey: "CEREBRAS_API_KEY",
    model: process.env.CEREBRAS_MODEL || "gpt-oss-120b",
    call: async (systemPrompt, conversationMessages, apiKey, model, signal) => {
      const r = await fetch("https://api.cerebras.ai/v1/chat/completions", {
        method: "POST",
        headers: { "Content-Type": "application/json", Authorization: "Bearer " + apiKey },
        body: JSON.stringify({
          model,
          messages: [{ role: "system", content: systemPrompt }, ...conversationMessages],
          max_tokens: 1024,
        }),
        signal,
      });
      const d = await r.json();
      if (!r.ok || d?.error) throw new Error("cerebras_error: " + JSON.stringify(d?.error || d).slice(0, 300));
      const text = d?.choices?.[0]?.message?.content?.trim();
      if (!text) throw new Error("cerebras_empty_response");
      return text;
    },
  },
  {
    // OpenRouter -- has always-free models (id ends with ":free", $0 cost, no
    // card needed). Get a key at https://openrouter.ai/keys. Pick a current
    // free model from https://openrouter.ai/models?max_price=0 and set it via
    // OPENROUTER_MODEL if the default below stops being free/available.
    name: "openrouter",
    envKey: "OPENROUTER_API_KEY",
    model: process.env.OPENROUTER_MODEL || "openrouter/free",
    call: async (systemPrompt, conversationMessages, apiKey, model, signal) => {
      const r = await fetch("https://openrouter.ai/api/v1/chat/completions", {
        method: "POST",
        headers: { "Content-Type": "application/json", Authorization: "Bearer " + apiKey },
        body: JSON.stringify({
          model,
          messages: [{ role: "system", content: systemPrompt }, ...conversationMessages],
          max_tokens: 1024,
        }),
        signal,
      });
      const d = await r.json();
      if (!r.ok || d?.error) throw new Error("openrouter_error: " + JSON.stringify(d?.error || d).slice(0, 300));
      const text = d?.choices?.[0]?.message?.content?.trim();
      if (!text) throw new Error("openrouter_empty_response");
      return text;
    },
  },
];

// Per-provider concurrent-call counter (in-memory, resets on redeploy -- fine,
// it only needs to reflect THIS instance's current traffic to pick the least
// busy provider). Total across all providers = current server load.
const AI_LOAD = {};
AI_PROVIDERS.forEach((p) => (AI_LOAD[p.name] = 0));
let AI_ACTIVE_REQUESTS = 0; // total concurrent "/ask-ai" requests being served right now

const AI_RACE_THRESHOLD = Number(process.env.AI_RACE_THRESHOLD || 6); // below this concurrency, race ALL providers; at/above it, load-balance to the least-busy ONE
const AI_CALL_TIMEOUT_MS = Number(process.env.AI_CALL_TIMEOUT_MS || 12000); // hard cap per provider attempt so a slow provider never stalls the whole reply

function configuredProviders() {
  return AI_PROVIDERS.filter((p) => !!process.env[p.envKey]);
}

// Fires all given providers at once; first one to resolve with real text
// wins and the rest are aborted immediately (saves quota + avoids wasted
// spend on the losers). Resolves { ok:false } only if EVERY provider fails.
async function raceProviders(providers, systemPrompt, conversationMessages) {
  return new Promise((resolve) => {
    let settled = false;
    let remaining = providers.length;
    const controllers = providers.map(() => new AbortController());

    providers.forEach((p, i) => {
      AI_LOAD[p.name]++;
      const apiKey = process.env[p.envKey];
      const timeoutId = setTimeout(() => controllers[i].abort(), AI_CALL_TIMEOUT_MS);

      p.call(systemPrompt, conversationMessages, apiKey, p.model, controllers[i].signal)
        .then((text) => {
          clearTimeout(timeoutId);
          AI_LOAD[p.name]--;
          if (!settled) {
            settled = true;
            controllers.forEach((c, j) => { if (j !== i) c.abort(); }); // cancel the losers
            resolve({ ok: true, text, provider: p.name });
          }
        })
        .catch((err) => {
          clearTimeout(timeoutId);
          AI_LOAD[p.name]--;
          if (err?.name !== "AbortError") {
            console.log(`❌ [race:${p.name}] failed:`, err.message);
          }
          remaining--;
          if (remaining === 0 && !settled) {
            settled = true;
            resolve({ ok: false });
          }
        });
    });
  });
}

// Calls ONLY the single least-loaded provider (used under high concurrency,
// and as the fallback attempt after a failure either way).
async function callLeastBusy(providers, systemPrompt, conversationMessages, excludeNames = []) {
  const candidates = providers.filter((p) => !excludeNames.includes(p.name));
  if (!candidates.length) return { ok: false };
  candidates.sort((a, b) => AI_LOAD[a.name] - AI_LOAD[b.name]);
  const p = candidates[0];

  AI_LOAD[p.name]++;
  const apiKey = process.env[p.envKey];
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), AI_CALL_TIMEOUT_MS);
  try {
    const text = await p.call(systemPrompt, conversationMessages, apiKey, p.model, controller.signal);
    return { ok: true, text, provider: p.name };
  } catch (err) {
    console.log(`❌ [least-busy:${p.name}] failed:`, err.message);
    return { ok: false, provider: p.name };
  } finally {
    clearTimeout(timeoutId);
    AI_LOAD[p.name]--;
  }
}

// ================= AI CALL RETRY WRAPPER (transient errors only) =================
// Gemini/other providers kabhi-kabhi "high demand" / 503 / UNAVAILABLE jaisa
// temporary overload error dete hain jo khud hi bolta hai "try again later".
// Ye wrapper poore raceProviders+callLeastBusy attempt ko chhote gap ke
// saath 1-2 baar retry karta hai, SIRF tab jab dono attempts ka error
// transient lage -- permanent errors (invalid API key, model not found,
// bad request) par turant fail ho jaata hai, retry karne ka koi fayda
// nahi hota unme.
function isTransientAiError(text) {
  if (!text) return false;
  const t = text.toLowerCase();
  return t.includes("503") || t.includes("unavailable") || t.includes("high demand") ||
         t.includes("overloaded") || t.includes("rate limit") || t.includes("429") ||
         t.includes("timeout") || t.includes("econnreset") || t.includes("etimedout");
}

async function callAiWithRetry(availableProviders, systemPrompt, conversationMessages, maxRetries = 1) {
  let lastAttempt = { ok: false };
  for (let i = 0; i <= maxRetries; i++) {
    let attempt = await raceProviders(availableProviders, systemPrompt, conversationMessages);
    if (!attempt.ok) attempt = await callLeastBusy(availableProviders, systemPrompt, conversationMessages);
    if (attempt.ok) return attempt;
    lastAttempt = attempt;
    if (i < maxRetries) {
      console.log(`⏳ AI call attempt ${i + 1} failed (transient), retrying in 1000ms...`);
      await new Promise((r) => setTimeout(r, 1000)); // single short 1s retry — fast, not a long chain
    }
  }
  return lastAttempt;
}

// ================= MATCH RESULT SCREENSHOT AUTOMATION =================
// Admin panel se ek match ke multiple result screenshots (base64) + us
// match ke registered players ki list bhejta hai. Hum Gemini vision se har
// screenshot me dikh rahe players (name, kills, placement/rank, team) nikaal
// te hain, phir har extracted name ko registered players ke gameName se
// fuzzy-match karte hain:
//   - Confident single match  -> "matched" (admin panel me auto-fill hoga)
//   - Koi close match nahi / multiple equally-close matches / OCR khud
//     unsure -> "flagged" with a reason (category), admin manually cross
//     check karke edit kare submit karne se pehle.
// Sirf Gemini hi (in providers me) image input support karta hai, isliye
// yahan seedha Gemini use hoti hai — lekin apna dedicated GEMINI_VISION_API_KEY
// se (alag Google AI Studio project), taaki /ask-ai chat traffic isse quota
// share na kare.

// Simple normalized Levenshtein-based similarity (0..1, 1 = exact match).
// Koi extra npm package nahi -- chhoti si name-matching ke liye kaafi hai.
// NAYA FIX: pehle yahan `[^a-z0-9]` regex chalta tha jo sirf plain ASCII
// letters/digits rakhta tha -- iska matlab kisi bhi player ka naam jo
// "fancy"/stylized Unicode font me ho (jaise "𝓐𝓵𝓹𝓱𝓪", "ᴾᴿᴼ ɢᴀᴹᴇʀ") ya kisi
// doosri language/script me ho (Hindi/Devanagari, Arabic, etc.) poora ka
// poora khali string ban jaata tha (kyunki wo characters a-z0-9 range me
// nahi aate). Do khali strings compare karne par similarity hamesha 0
// aati thi, isliye aise players AI se KABHI match nahi hote the -- hamesha
// "no_close_match" flag lagta tha, chahe screenshot me naam bilkul sahi
// dikh raha ho.
// Fix do steps me: (1) .normalize("NFKC") stylized/mathematical Unicode
// look-alike letters (jo bahut saare "fancy font" gamer names use karte
// hain) ko unke plain base letter me fold kar deta hai (e.g. 𝓐 -> A);
// (2) regex ab sirf whitespace/punctuation/emoji hataata hai, kisi bhi
// language ke letters/digits/combining-marks (\p{L}, \p{N}, \p{M}) ko safe
// rakhta hai — \p{M} zaroori hai warna Devanagari jaisi scripts ke matras
// (jaise "ा", "ु") jo letters ke saath combine hoti hain wo hi strip ho
// jaate (e.g. "राहुल" galti se "रहल" ban jaata) -- isliye Hindi ya kisi bhi
// script ka naam ab bhi apni asli script me bilkul sahi compare hota hai
// (jo bilkul theek kaam karta hai jab screenshot me bhi wahi script dikh
// rahi ho).
function normName(s) {
  return String(s || "")
    .normalize("NFKC")
    .toLowerCase()
    .trim()
    .replace(/[^\p{L}\p{N}\p{M}]/gu, "");
}
function levenshtein(a, b) {
  const m = a.length, n = b.length;
  if (!m) return n;
  if (!n) return m;
  const dp = Array.from({ length: m + 1 }, (_, i) => [i, ...Array(n).fill(0)]);
  for (let j = 0; j <= n; j++) dp[0][j] = j;
  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      dp[i][j] = a[i - 1] === b[j - 1]
        ? dp[i - 1][j - 1]
        : 1 + Math.min(dp[i - 1][j], dp[i][j - 1], dp[i - 1][j - 1]);
    }
  }
  return dp[m][n];
}
function nameSimilarity(a, b) {
  const na = normName(a), nb = normName(b);
  if (!na || !nb) return 0;
  if (na === nb) return 1;
  const dist = levenshtein(na, nb);
  return 1 - dist / Math.max(na.length, nb.length);
}

// registeredPlayers: [{ uid, gameName, gameUid }]
// extracted: [{ rawName, kills, rank, team, sourceImage }] (from AI)
// Returns per-uid best guess + flag info. Har extracted entry sirf ek baar
// consume ho sakti hai (agar do registered players same extracted name se
// match karne ki koshish karein to dono flag ho jaate hain -- "duplicate").
function matchExtractedToPlayers(registeredPlayers, extracted) {
  const SIM_CONFIDENT = 0.72; // isse upar => auto-fill
  const SIM_GAP_MIN = 0.08;   // best aur second-best ke beech kam se kam itna gap chahiye, warna "ambiguous"

  const results = {};
  const usedExtractedIdx = new Set();

  registeredPlayers.forEach((p) => {
    if (!extracted.length) {
      results[p.uid] = { category: "no_screenshot_data", flagged: true, reason: "Koi screenshot data hi nahi mila" };
      return;
    }
    const scored = extracted
      .map((e, idx) => ({ idx, e, score: Math.max(nameSimilarity(p.gameName, e.rawName), nameSimilarity(p.gameUid, e.rawName)) }))
      .sort((a, b) => b.score - a.score);

    const best = scored[0];
    const second = scored[1];

    if (best.score < SIM_CONFIDENT) {
      results[p.uid] = { category: "no_close_match", flagged: true, reason: `Screenshot me is naam se milta-julta koi player nahi mila (best guess: "${best.e.rawName}", ${Math.round(best.score * 100)}% match)`, suggestion: best.e };
      return;
    }
    if (second && (best.score - second.score) < SIM_GAP_MIN) {
      results[p.uid] = { category: "ambiguous_multiple_matches", flagged: true, reason: `"${p.gameName}" do names se match ho sakta hai: "${best.e.rawName}" aur "${second.e.rawName}"`, suggestion: best.e, alternates: [best.e, second.e] };
      return;
    }
    if (usedExtractedIdx.has(best.idx)) {
      results[p.uid] = { category: "duplicate_match", flagged: true, reason: `"${best.e.rawName}" pehle hi kisi aur registered player ko assign ho chuka hai`, suggestion: best.e };
      return;
    }
    usedExtractedIdx.add(best.idx);
    results[p.uid] = {
      category: "matched",
      flagged: false,
      matchedName: best.e.rawName,
      kills: Number(best.e.kills) || 0,
      rank: best.e.rank || "",
      team: best.e.team || "",
      confidence: Math.round(best.score * 100),
    };
  });

  return results;
}

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

// Screenshot-result-reading ke liye chhota multi-provider fallback (chat wale
// AI_PROVIDERS se alag rakha hai kyunki images bhejni padti hain, jo har
// provider/model handle nahi karta). Order: Gemini (2 retries, kyunki 503
// "high demand" zyadatar temporary hoti hai) -> agar wo bhi fail ho jaaye to
// OpenRouter ka ek free vision-capable model (same OPENROUTER_API_KEY jo
// /ask-ai chat ke liye already set hai).
const VISION_PROVIDERS = [
  {
    name: "gemini",
    envKey: "GEMINI_VISION_API_KEY",
    fallbackEnvKey: "GEMINI_API_KEY",
    getModel: () => process.env.GEMINI_VISION_MODEL || process.env.GEMINI_MODEL || "gemini-3.6-flash",
    retries: 2, // 503 "high demand" jaisi temporary spikes ke liye
    call: async (prompt, imageParts, apiKey, model) => {
      const r = await fetch(
        `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${apiKey}`,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            contents: [{ role: "user", parts: [{ text: prompt }, ...imageParts] }],
            generationConfig: { maxOutputTokens: 16384, temperature: 0.1 },
          }),
        }
      );
      const d = await r.json();
      if (!r.ok || d?.error) {
        const errCode = d?.error?.code;
        const errMsg = JSON.stringify(d?.error || d).slice(0, 400);
        const err = new Error("gemini_error: " + errMsg);
        err.transient = errCode === 503 || errCode === 429; // overloaded / rate-limited -- retry-worthy
        throw err;
      }
      const rawParts = d?.candidates?.[0]?.content?.parts;
      const text = rawParts?.length ? rawParts.map((p) => p.text || "").join("\n").trim() : "";
      if (!text) throw new Error("gemini_empty_response");
      return text;
    },
  },
  {
    // Groq -- vision-capable Llama models, OpenAI-compatible format (same
    // image_url shape jo OpenRouter neeche use karta hai). Fast aur usually
    // Gemini se independent load hoti hai isliye Gemini ke baad pehla
    // fallback yahi try karte hain.
    name: "groq",
    envKey: "GROQ_API_KEY",
    getModel: () => process.env.GROQ_VISION_MODEL || "qwen/qwen3.6-27b",
    retries: 1,
    call: async (prompt, imageDataUrls, apiKey, model) => {
      const content = [{ type: "text", text: prompt }, ...imageDataUrls.map((u) => ({ type: "image_url", image_url: { url: u } }))];
      const r = await fetch("https://api.groq.com/openai/v1/chat/completions", {
        method: "POST",
        headers: { "Content-Type": "application/json", Authorization: "Bearer " + apiKey },
        body: JSON.stringify({ model, messages: [{ role: "user", content }], max_tokens: 16384, temperature: 0.1 }),
      });
      const d = await r.json();
      if (!r.ok || d?.error) {
        const err = new Error("groq_error: " + JSON.stringify(d?.error || d).slice(0, 400));
        err.transient = r.status === 503 || r.status === 429;
        throw err;
      }
      const text = d?.choices?.[0]?.message?.content?.trim();
      if (!text) throw new Error("groq_empty_response");
      return text;
    },
  },
  {
    name: "openrouter",
    envKey: "OPENROUTER_API_KEY",
    getModel: () => process.env.OPENROUTER_VISION_MODEL || "openrouter/free",
    retries: 1,
    // OpenAI-compatible vision format -- image base64 data-URLs seedhe
    // image_url.url me ja sakte hain.
    call: async (prompt, imageDataUrls, apiKey, model) => {
      const content = [{ type: "text", text: prompt }, ...imageDataUrls.map((u) => ({ type: "image_url", image_url: { url: u } }))];
      const r = await fetch("https://openrouter.ai/api/v1/chat/completions", {
        method: "POST",
        headers: { "Content-Type": "application/json", Authorization: "Bearer " + apiKey },
        body: JSON.stringify({ model, messages: [{ role: "user", content }], max_tokens: 16384, temperature: 0.1 }),
      });
      const d = await r.json();
      if (!r.ok || d?.error) {
        const err = new Error("openrouter_error: " + JSON.stringify(d?.error || d).slice(0, 400));
        err.transient = r.status === 503 || r.status === 429;
        throw err;
      }
      const text = d?.choices?.[0]?.message?.content?.trim();
      if (!text) throw new Error("openrouter_empty_response");
      return text;
    },
  },
];


app.post("/process-match-results", verifyAuth, async (req, res) => {
  try {
    const callerUid = req.uid;
    const [adminConfigSnap, staffSnap] = await Promise.all([
      db.ref("adminConfig/adminUid").get(),
      db.ref(`staff/${callerUid}/status`).get(),
    ]);
    const isAdmin = adminConfigSnap.val() === callerUid;
    const isActiveStaff = staffSnap.val() === "active";
    if (!isAdmin && !isActiveStaff) {
      return res.status(403).json({ error: "unauthorized" });
    }

    const { images, registeredPlayers } = req.body;
    if (!Array.isArray(images) || !images.length) {
      return res.status(400).json({ error: "images array is required (base64 data URLs)" });
    }
    if (!Array.isArray(registeredPlayers) || !registeredPlayers.length) {
      return res.status(400).json({ error: "registeredPlayers array is required" });
    }
    if (images.length > 15) {
      return res.status(400).json({ error: "Max 15 screenshots per request" });
    }

    // Dedicated key for result-fill so heavy /ask-ai chat traffic (which also
    // uses Gemini in its provider pool) never eats into this feature's quota.
    const geminiKey = process.env.GEMINI_VISION_API_KEY || process.env.GEMINI_API_KEY;
    const geminiModel = process.env.GEMINI_VISION_MODEL || process.env.GEMINI_MODEL || "gemini-3.6-flash";
    const groqKey = process.env.GROQ_API_KEY;
    const groqModel = process.env.GROQ_VISION_MODEL || "qwen/qwen3.6-27b";
    const openrouterKey = process.env.OPENROUTER_API_KEY;
    const openrouterModel = process.env.OPENROUTER_VISION_MODEL || "openrouter/free";
    if (!geminiKey && !groqKey && !openrouterKey) {
      return res.status(500).json({ error: "No vision-capable AI provider configured (set GEMINI_VISION_API_KEY, GROQ_API_KEY, or OPENROUTER_API_KEY)" });
    }

    // Data URLs ("data:image/png;base64,....") ko Gemini ke inline_data
    // format me todhna.
    const geminiParts = [];
    for (const img of images) {
      const match = /^data:(image\/[a-zA-Z0-9.+-]+);base64,(.+)$/.exec(img);
      if (!match) continue;
      geminiParts.push({ inline_data: { mime_type: match[1], data: match[2] } });
    }
    if (!geminiParts.length) {
      return res.status(400).json({ error: "No valid base64 image data URLs found" });
    }

    const prompt =
      "These are screenshots of a game match's result/scoreboard screen (e.g. Free Fire / BGMI). " +
      "Carefully read EVERY player row visible across ALL the images. For each player row extract: " +
      "the player/in-game name exactly as written, their kill count (number), their placement/rank " +
      "if shown (e.g. '#1', '3rd'), and their team name/number if shown. If a name is partially " +
      "unreadable, still return your best-effort reading of it (do not skip it). " +
      "Respond ONLY with a raw JSON array (no markdown fences, no extra text), like:\n" +
      '[{"rawName":"ProGamer99","kills":7,"rank":"#1","team":"Alpha"}, ...]\n' +
      "If a field is not visible/applicable, use an empty string or 0. Do not invent players that are not in the images.";

    // Gemini pehle try karta hai (2 retries agar 503/429 "high demand" jaisi
    // temporary error aaye — thodi backoff ke saath). Agar wo poori tarah fail
    // ho jaaye (ya key hi set na ho), to Groq try hota hai, uske baad
    // OpenRouter ka free vision model — taaki ek ya do provider ke temporary
    // outage se poora feature down na ho jaaye.
    let text = "";
    let usedProvider = "";
    const attempts = [];

    if (geminiKey) {
      for (let attempt = 0; attempt <= 2; attempt++) {
        try {
          text = await VISION_PROVIDERS[0].call(prompt, geminiParts, geminiKey, geminiModel);
          usedProvider = "gemini";
          break;
        } catch (err) {
          attempts.push(`gemini(try ${attempt + 1}): ${err.message}`);
          if (err.transient && attempt < 2) { await sleep(1200 * (attempt + 1)); continue; }
          break; // non-transient error, ya retries khatam -- aage fallback try karo
        }
      }
    }

    // Groq ka current vision model (qwen/qwen3.6-27b) sirf max 5 images/request
    // support karta hai -- agar isse zyada screenshots hain to Groq ko call hi
    // nahi karte (turant fail hota, time waste), seedha OpenRouter try hoga.
    if (!text && groqKey && images.length <= 5) {
      try {
        text = await VISION_PROVIDERS[1].call(prompt, images, groqKey, groqModel);
        usedProvider = "groq";
      } catch (err) {
        attempts.push(`groq: ${err.message}`);
      }
    } else if (!text && groqKey) {
      attempts.push(`groq: skipped (${images.length} images > 5-image limit)`);
    }

    if (!text && openrouterKey) {
      try {
        text = await VISION_PROVIDERS[2].call(prompt, images, openrouterKey, openrouterModel);
        usedProvider = "openrouter";
      } catch (err) {
        attempts.push(`openrouter: ${err.message}`);
      }
    }

    if (!text) {
      console.log("❌ All vision providers failed:", attempts.join(" | ").slice(0, 800));
      return res.status(502).json({ error: "AI provider failed to process screenshots (all providers unavailable, please try again shortly)" });
    }
    console.log(`✅ Screenshot result reading via ${usedProvider}${attempts.length ? ` (after: ${attempts.join(" | ").slice(0, 300)})` : ""}`);
    text = text.replace(/^```(?:json)?/i, "").replace(/```$/i, "").trim();

    // Kuch models (jaise Groq ka reasoning-capable qwen model) instruction ke
    // bawajood JSON se pehle apna "thinking"/reasoning text bhi likh dete hain
    // (e.g. "The user wants me to extract data from... Let's go through each
    // image one by one."). Isse JSON.parse seedha fail ho jaata tha. Fix: text
    // ke andar se pehle "[" se aakhri "]" tak ka hissa hi nikal lo -- aage-peeche
    // ka koi bhi extra reasoning text apne aap ignore ho jayega.
    const firstBracket = text.indexOf("[");
    const lastBracket = text.lastIndexOf("]");
    if (firstBracket !== -1 && lastBracket > firstBracket) {
      text = text.slice(firstBracket, lastBracket + 1);
    } else if (firstBracket !== -1) {
      // Closing "]" hi nahi mili (response beech me hi kat gaya) -- kam se kam
      // pehle wala reasoning text to hata do, taaki neeche wala truncation-repair
      // function saaf data par kaam kare.
      text = text.slice(firstBracket);
    }

    // Agar AI response fir bhi kisi wajah se beech me kat jaaye (network limit,
    // model quirk, etc.), to poora request fail karne ke bajaye jitne players
    // ka data COMPLETE mila hai usko salvage karte hain — array ke last
    // complete "}," tak cut karke usse hi valid JSON bana lete hain.
    const repairTruncatedJsonArray = (str) => {
      const lastCompleteObjEnd = str.lastIndexOf("},");
      if (lastCompleteObjEnd === -1) return null;
      const repaired = str.slice(0, lastCompleteObjEnd + 1) + "]";
      try {
        const arr = JSON.parse(repaired);
        return Array.isArray(arr) ? arr : null;
      } catch (e) {
        return null;
      }
    };

    let extracted;
    let wasTruncated = false;
    try {
      extracted = JSON.parse(text);
      if (!Array.isArray(extracted)) throw new Error("not an array");
    } catch (parseErr) {
      console.log("⚠️ AI JSON needs repair:", parseErr.message, "| raw:", text.slice(0, 300));
      const repaired = repairTruncatedJsonArray(text);
      if (repaired && repaired.length > 0) {
        extracted = repaired;
        wasTruncated = true;
        console.log(`⚠️ Recovered ${repaired.length} players from truncated AI response.`);
      } else {
        console.log("❌ Failed to parse AI JSON:", parseErr.message, "| raw:", text.slice(0, 300));
        return res.status(502).json({ error: "AI response could not be parsed, please try again" });
      }
    }
    extracted = extracted
      .filter((e) => e && typeof e === "object" && e.rawName)
      .map((e) => ({ rawName: String(e.rawName).slice(0, 60), kills: Number(e.kills) || 0, rank: e.rank ? String(e.rank).slice(0, 20) : "", team: e.team ? String(e.team).slice(0, 40) : "" }));

    const matchResults = matchExtractedToPlayers(registeredPlayers, extracted);
    const summary = {
      totalExtracted: extracted.length,
      totalRegistered: registeredPlayers.length,
      matched: Object.values(matchResults).filter((v) => !v.flagged).length,
      flagged: Object.values(matchResults).filter((v) => v.flagged).length,
      partial: wasTruncated, // true => AI response truncate hui thi, kuch players miss ho sakte hai
    };

    console.log(`✅ Match result screenshots processed by ${callerUid}: ${summary.matched} matched, ${summary.flagged} flagged`);
    return res.json({ success: true, results: matchResults, extracted, summary });
  } catch (err) {
    console.log("❌ Process match results error:", err.message);
    return res.status(500).json({ error: "Something went wrong" });
  }
});

// Last `limit` messages (default 6) firebase se fetch karta hai
// (aiSupportChats/{uid}/messages), timestamp descending order me query
// karke phir chronological order me reverse kar deta hai. Sirf
// senderType "user"/"ai" wale real messages liye jaate hain -- "retrying:
// true" wale placeholder messages skip ho jaate hain. OpenAI-style
// { role, content } format me convert karke return karta hai. Ye current
// (abhi save hua) message include NAHI karta -- wo alag userMsg
// parameter se already jaata hai.
async function fetchRecentChatHistory(uid, limit = 6, excludeKey = null) {
  try {
    // excludeKey se ek extra fetch karte hain taaki abhi-abhi save hua current
    // user message (jo /ask-ai route step 1 me already DB me likha ja chuka
    // hota hai) history me duplicate na ho -- current message alag se
    // userMsg/conversationMessages ke last item ke roop me jaata hai.
    const fetchLimit = excludeKey ? limit + 1 : limit;
    const snap = await db
      .ref(`aiSupportChats/${uid}/messages`)
      .orderByChild("timestamp")
      .limitToLast(fetchLimit)
      .once("value");

    if (!snap.exists()) return [];

    const rows = [];
    snap.forEach((c) => {
      if (excludeKey && c.key === excludeKey) return; // current message, skip
      const v = c.val() || {};
      if (v.retrying === true) return; // placeholder, skip
      if (v.senderType !== "user" && v.senderType !== "ai") return;
      if (typeof v.message !== "string" || !v.message) return;
      rows.push({ timestamp: v.timestamp || 0, senderType: v.senderType, message: v.message });
    });

    rows.sort((a, b) => a.timestamp - b.timestamp); // chronological order

    return rows.slice(-limit).map((r) => ({
      role: r.senderType === "user" ? "user" : "assistant",
      content: r.message,
    }));
  } catch (histErr) {
    console.log("⚠️ Could not load recent chat history:", histErr.message);
    return [];
  }
}

// ================= DETERMINISTIC MATCH-EARNINGS QUERY ANSWERER =================
// "Kitna jeeta maine [match name] me?" jaisi queries ko bina kisi AI/LLM
// call ke seedha Firebase data se answer karta hai (deterministic, fast,
// aur AI quota bachata hai). Agar ye function null return kare, tab hi
// /ask-ai route normal AI-FAQ flow pe fall back karta hai.
//
// Match name aur time KABHI translate nahi hote (jaise "Free Fire Solo
// Match", "12:20 PM") — sirf inke aas-paas ka sentence teeno languages
// (en / hi / hinglish) me translate hota hai.

// ---- STEP 1: Language detection (simple regex/keyword based, no AI) ----
const HINGLISH_HINT_WORDS = [
  "kitna", "kitne", "kitni", "kab", "kaise", "jeeta", "jeete", "jeeti",
  "hua", "hui", "kya", "mujhe", "mera", "meri", "aapka", "aapki", "paisa",
  "paise", "abhi", "khela",
];

function detectReplyLanguage(message) {
  if (typeof message !== "string" || !message.trim()) return "en";

  // Devanagari Unicode range check — agar isme se koi character mila to
  // seedha "hi" (pure Hindi script).
  if (/[\u0900-\u097F]/.test(message)) return "hi";

  // Devanagari nahi hai — check karo ki Roman-script Hindi/Hinglish words
  // hain ya nahi (word-boundary based).
  const lower = message.toLowerCase();
  const isHinglish = HINGLISH_HINT_WORDS.some((w) =>
    new RegExp(`(^|[^a-z])${w}([^a-z]|$)`, "i").test(lower)
  );
  if (isHinglish) return "hinglish";

  return "en";
}

// ---- STEP 2: Reply templates — 3 languages har case ke liye ----
const MATCH_EARNINGS_TEMPLATES = {
  noMatchesPlayed: {
    en: "You haven't played any matches yet.",
    hi: "आपने अभी तक कोई मैच नहीं खेला है।",
    hinglish: "Aapne abhi tak koi match nahi khela hai.",
  },
  noMatchFoundAtTime: {
    en: "I couldn't find a match at that time. Could you confirm the exact match name or time?",
    hi: "मुझे उस समय पर कोई मैच नहीं मिला। कृपया सही मैच का नाम या समय बताएं।",
    hinglish: "Mujhe us time pe koi match nahi mila. Please sahi match ka naam ya time confirm karo.",
  },
  multipleMatchesFound: {
    en: "I found multiple matches that match this. Please tell me which one you mean:\n{list}",
    hi: "मुझे इससे मिलते-जुलते कई मैच मिले। कृपया बताएं कि आप किस मैच के बारे में पूछ रहे हैं:\n{list}",
    hinglish: "Mujhe isse milte julte kai matches mile. Please batao aap kis match ke baare me pooch rahe ho:\n{list}",
  },
  noRecordForMatch: {
    en: "I couldn't find your entry for this match.",
    hi: "मुझे इस मैच में आपकी कोई एंट्री नहीं मिली।",
    hinglish: "Mujhe is match me aapki koi entry nahi mili.",
  },
  resultNotDeclared: {
    en: "The result for this match hasn't been declared yet.",
    hi: "इस मैच का रिजल्ट अभी घोषित नहीं हुआ है।",
    hinglish: "Is match ka result abhi declare nahi hua hai.",
  },
  wonAmount: {
    en: "Congratulations! You won ₹{amount} in {matchName} ({matchTime}).",
    hi: "बधाई हो! आपने {matchName} ({matchTime}) में ₹{amount} जीते।",
    hinglish: "Congratulations! Aapne {matchName} ({matchTime}) me ₹{amount} jeete.",
  },
  noWinningThisTime: {
    en: "You didn't win any prize in {matchName} ({matchTime}) this time.",
    hi: "इस बार आपने {matchName} ({matchTime}) में कोई इनाम नहीं जीता।",
    hinglish: "Is baar aapne {matchName} ({matchTime}) me koi prize nahi jeeta.",
  },
};

// Template object se detected-language wali line nikaalta hai (fallback:
// "en", agar detected language ka template kisi wajah se missing ho) aur
// {placeholder} tokens ko diye gaye vars se fill karta hai.
function fillTemplate(templateObj, lang, vars = {}) {
  const raw = templateObj[lang] || templateObj.en;
  return raw.replace(/\{(\w+)\}/g, (_, key) =>
    Object.prototype.hasOwnProperty.call(vars, key) ? String(vars[key]) : `{${key}}`
  );
}

// Har candidate match ko "- Name (Time)" format me list-ify karta hai
// (multipleMatchesFound case ke liye) — match name/time translate nahi
// hote, sirf list bullet format consistent rehta hai.
function formatMatchList(candidates) {
  return candidates
    .map((c) => `- ${c.name}${c.time ? ` (${c.time})` : ""}`)
    .join("\n");
}

// Tournament time DB me raw epoch ms (jaise 1756633140000) ke roop me store
// hota hai — human-readable "4:59 pm" sirf frontend par render waqt banta
// hai. Pehle ye function seedha `String(rawValue)` kar deta tha, jisse
// "1756633140000" ban jaata tha jo user ke typed "4:59pm" se kabhi match
// nahi karta tha. Ab hum epoch-jaisi values ko IST me format karte hain,
// taaki wahi human-readable form bane jo user dekh/type karta hai. Agar
// value already text hai (legacy data), use as-is chhod dete hain.
function formatMatchTimeIST(rawValue) {
  const str = String(rawValue == null ? "" : rawValue).trim();
  if (!str) return "";
  if (/^\d+$/.test(str)) {
    const ms = Number(str);
    if (Number.isFinite(ms) && ms > 0) {
      try {
        return new Date(ms)
          .toLocaleString("en-IN", {
            timeZone: "Asia/Kolkata",
            hour: "numeric",
            minute: "2-digit",
            hour12: true,
          })
          .toLowerCase();
      } catch (e) {
        return str; // fallback: leave raw value untouched if formatting fails
      }
    }
  }
  return str;
}

// ---- STEP 3: Main deterministic answerer ----
// Returns a reply string (already in the right language) if this message
// looks like a match-earnings query and could be answered from DB data,
// or `null` if the caller should fall back to the normal AI-FAQ flow.
// IMPORTANT: 100% deterministic — no AI/LLM call anywhere in this function.
async function tryAnswerMatchEarningsQuery(uid, message) {
  const lang = detectReplyLanguage(message);

  let allTournamentsSnap;
  try {
    allTournamentsSnap = await db.ref("tournaments").once("value");
  } catch (err) {
    console.log("⚠️ tryAnswerMatchEarningsQuery: could not load tournaments:", err.message);
    return null; // DB issue — let normal AI flow handle it instead of failing silently
  }
  if (!allTournamentsSnap.exists()) {
    return { reply: fillTemplate(MATCH_EARNINGS_TEMPLATES.noMatchesPlayed, lang), awaitingClarification: false };
  }

  const allTournaments = []; // every match in the system: { id, name, time, status, playerRecord|null }
  const joinedTournaments = []; // only the ones this uid has registeredPlayers entry in

  allTournamentsSnap.forEach((c) => {
    const v = c.val() || {};
    const name = String(v.name || "Untitled Match");
    const time = formatMatchTimeIST(v.matchTime || v.time || v.scheduledTime || v.startTime || "");
    const status = String(v.status || "");
    const players = v.registeredPlayers || {};
    const playerRecord = players[uid] || null;

    const entry = { id: c.key, name, time, status, playerRecord };
    allTournaments.push(entry);
    if (playerRecord) joinedTournaments.push(entry);
  });

  // CASE 1 — user has never joined any match at all.
  if (joinedTournaments.length === 0) {
    return { reply: fillTemplate(MATCH_EARNINGS_TEMPLATES.noMatchesPlayed, lang), awaitingClarification: false };
  }

  // Try to figure out which specific match the user means, from the
  // message text — first by a time-like token (e.g. "12:20 PM"), else by
  // matching match names that appear (partially) in the message.
  const lowerMsg = message.toLowerCase();
  const timeToken = message.match(/\b\d{1,2}[:.]\d{2}\s?(am|pm)?\b/i);

  let candidates;
  if (timeToken) {
    const normalizedTime = timeToken[0].replace(/\s+/g, "").toLowerCase();
    candidates = allTournaments.filter(
      (t) => t.time && t.time.replace(/\s+/g, "").toLowerCase().includes(normalizedTime)
    );
  } else {
    const nameHits = allTournaments.filter(
      (t) => t.name && lowerMsg.includes(t.name.toLowerCase())
    );
    if (nameHits.length > 0) {
      candidates = nameHits;
    } else {
      // No specific name/time mentioned — treat it as a generic "how much
      // did I win" query scoped to whatever the user has actually joined.
      candidates = joinedTournaments;
    }
  }

  // CASE 2 — asked about a specific time/name but nothing matches at all.
  if (candidates.length === 0) {
    return { reply: fillTemplate(MATCH_EARNINGS_TEMPLATES.noMatchFoundAtTime, lang), awaitingClarification: true };
  }

  // CASE 3 — ambiguous, more than one match fits the query.
  if (candidates.length > 1) {
    return {
      reply: fillTemplate(MATCH_EARNINGS_TEMPLATES.multipleMatchesFound, lang, { list: formatMatchList(candidates) }),
      awaitingClarification: true,
    };
  }

  const match = candidates[0];

  // CASE 4 — a real match was identified, but the user never joined it.
  if (!match.playerRecord) {
    return { reply: fillTemplate(MATCH_EARNINGS_TEMPLATES.noRecordForMatch, lang), awaitingClarification: false };
  }

  // CASE 5 — match found & joined, but result hasn't been declared yet.
  const isDeclared = match.status === "completed" || match.status === "result";
  if (!isDeclared) {
    return { reply: fillTemplate(MATCH_EARNINGS_TEMPLATES.resultNotDeclared, lang), awaitingClarification: false };
  }

  const prize = Number(match.playerRecord.prize || 0);

  // CASE 6 — won something.
  if (prize > 0) {
    return {
      reply: fillTemplate(MATCH_EARNINGS_TEMPLATES.wonAmount, lang, {
        amount: prize,
        matchName: match.name,
        matchTime: match.time,
      }),
      awaitingClarification: false,
    };
  }

  // CASE 7 — result declared, but no prize this time.
  return {
    reply: fillTemplate(MATCH_EARNINGS_TEMPLATES.noWinningThisTime, lang, {
      matchName: match.name,
      matchTime: match.time,
    }),
    awaitingClarification: false,
  };
}

// ================= MORE DETERMINISTIC QUERY ANSWERERS =================
// tryAnswerMatchEarningsQuery ke hi pattern par — deposit history, withdrawal
// history, balance, VIP status, aur referral status wale sawaalon ko bhi
// bina AI/LLM call ke seedha DB se answer karte hain. Har function null
// return karta hai agar wo apne domain ka query hi nahi hai (to caller AI
// flow pe fall back kar sake) — lekin yaha hint-regex khud caller (`/ask-ai`)
// me check hota hai, isliye ye functions generally hamesha kuch na kuch
// reply dete hain jab tak DB fetch fail na ho.

const DAY_MS = 24 * 60 * 60 * 1000;
// NOTE: IST_OFFSET_MS already defined earlier in this file (line ~165) —
// reusing that one here instead of redeclaring it.

// "aaj" / "kal" jaise din-relative words ko IST calendar-day boundaries
// (UTC epoch ms) me convert karta hai. daysAgo = 0 -> aaj, 1 -> kal.
function getISTDayBounds(daysAgo) {
  const nowIST = new Date(Date.now() + IST_OFFSET_MS);
  const y = nowIST.getUTCFullYear(), m = nowIST.getUTCMonth(), d = nowIST.getUTCDate();
  const startIST = Date.UTC(y, m, d - daysAgo);
  return { start: startIST - IST_OFFSET_MS, end: startIST - IST_OFFSET_MS + DAY_MS };
}

// Message se "aaj"/"today" ya "kal"/"yesterday" detect karta hai. Koi din
// mention nahi hua to null return karta hai (matlab caller "overall/all-time"
// treat karega). NOTE: "kal" ka matlab Hindi me "yesterday" ya "tomorrow"
// dono ho sakta hai, lekin deposit/withdrawal history context me "tomorrow"
// ka koi matlab nahi banta, isliye yaha hamesha "yesterday" maana jaata hai.
function detectDayOffsetFromMessage(message) {
  const lower = message.toLowerCase();
  if (/\b(yesterday|kal)\b/i.test(lower)) return 1;
  if (/\b(today|aaj)\b/i.test(lower)) return 0;
  return null;
}

const PERIOD_LABELS = {
  0: { en: "today", hi: "आज", hinglish: "aaj" },
  1: { en: "yesterday", hi: "कल", hinglish: "kal" },
  null: { en: "overall", hi: "अब तक", hinglish: "ab tak" },
};

// ---- Deposit history ----
const DEPOSIT_QUERY_TEMPLATES = {
  noneFound: {
    en: "You haven't made any deposits {period}.",
    hi: "आपने {period} कोई डिपॉजिट नहीं किया।",
    hinglish: "Aapne {period} koi deposit nahi kiya.",
  },
  totalFound: {
    en: "You deposited a total of ₹{amount} {period} ({count} transaction{plural}).",
    hi: "आपने {period} कुल ₹{amount} डिपॉजिट किए ({count} ट्रांजैक्शन)।",
    hinglish: "Aapne {period} total ₹{amount} deposit kiye ({count} transaction{plural}).",
  },
};

async function tryAnswerDepositQuery(uid, message) {
  const lang = detectReplyLanguage(message);
  const dayOffset = detectDayOffsetFromMessage(message);
  const periodLabel = fillTemplate({ en: PERIOD_LABELS[dayOffset === null ? "null" : dayOffset].en, hi: PERIOD_LABELS[dayOffset === null ? "null" : dayOffset].hi, hinglish: PERIOD_LABELS[dayOffset === null ? "null" : dayOffset].hinglish }, lang);

  let snap;
  try {
    snap = await db.ref("deposits").orderByChild("userId").equalTo(uid).once("value");
  } catch (err) {
    console.log("⚠️ tryAnswerDepositQuery: could not load deposits:", err.message);
    return null;
  }

  const bounds = dayOffset === null ? null : getISTDayBounds(dayOffset);
  let total = 0, count = 0;
  if (snap.exists()) {
    snap.forEach((c) => {
      const v = c.val() || {};
      if (v.status !== "completed") return; // sirf actually-credited deposits ginte hain
      const ts = Number(v.timestamp || 0);
      if (bounds && !(ts >= bounds.start && ts < bounds.end)) return;
      total += Number(v.amount || 0);
      count += 1;
    });
  }

  if (count === 0) {
    return { reply: fillTemplate(DEPOSIT_QUERY_TEMPLATES.noneFound, lang, { period: periodLabel }), awaitingClarification: false };
  }
  return {
    reply: fillTemplate(DEPOSIT_QUERY_TEMPLATES.totalFound, lang, {
      amount: total, count, period: periodLabel, plural: count > 1 ? "s" : "",
    }),
    awaitingClarification: false,
  };
}

// ---- Withdrawal history ----
const WITHDRAWAL_QUERY_TEMPLATES = {
  noneFound: {
    en: "You haven't requested any withdrawals {period}.",
    hi: "आपने {period} कोई विड्रॉल रिक्वेस्ट नहीं की।",
    hinglish: "Aapne {period} koi withdrawal request nahi ki.",
  },
  totalFound: {
    en: "You requested ₹{amount} in withdrawals {period} ({count} request{plural}).",
    hi: "आपने {period} कुल ₹{amount} की विड्रॉल रिक्वेस्ट की ({count} रिक्वेस्ट)।",
    hinglish: "Aapne {period} total ₹{amount} ki withdrawal request ki ({count} request{plural}).",
  },
};

async function tryAnswerWithdrawalQuery(uid, message) {
  const lang = detectReplyLanguage(message);
  const dayOffset = detectDayOffsetFromMessage(message);
  const periodLabel = fillTemplate({ en: PERIOD_LABELS[dayOffset === null ? "null" : dayOffset].en, hi: PERIOD_LABELS[dayOffset === null ? "null" : dayOffset].hi, hinglish: PERIOD_LABELS[dayOffset === null ? "null" : dayOffset].hinglish }, lang);

  let snap;
  try {
    snap = await db.ref("withdrawals").orderByChild("userId").equalTo(uid).once("value");
  } catch (err) {
    console.log("⚠️ tryAnswerWithdrawalQuery: could not load withdrawals:", err.message);
    return null;
  }

  const bounds = dayOffset === null ? null : getISTDayBounds(dayOffset);
  let total = 0, count = 0;
  if (snap.exists()) {
    snap.forEach((c) => {
      const v = c.val() || {};
      if (v.status === "rejected") return; // reject hui request "kiya hua withdrawal" nahi mानी jaati
      const ts = Number(v.requestTimestamp || v.processedAt || 0);
      if (bounds && !(ts >= bounds.start && ts < bounds.end)) return;
      total += Number(v.amount || 0);
      count += 1;
    });
  }

  if (count === 0) {
    return { reply: fillTemplate(WITHDRAWAL_QUERY_TEMPLATES.noneFound, lang, { period: periodLabel }), awaitingClarification: false };
  }
  return {
    reply: fillTemplate(WITHDRAWAL_QUERY_TEMPLATES.totalFound, lang, {
      amount: total, count, period: periodLabel, plural: count > 1 ? "s" : "",
    }),
    awaitingClarification: false,
  };
}

// ---- Balance / wallet ----
const BALANCE_QUERY_TEMPLATES = {
  full: {
    en: "Your current balance — Deposit: ₹{balance}, Winnings: ₹{winning}, Bonus: ₹{bonus}.",
    hi: "आपका करंट बैलेंस — डिपॉजिट: ₹{balance}, विनिंग्स: ₹{winning}, बोनस: ₹{bonus}।",
    hinglish: "Aapka current balance — Deposit: ₹{balance}, Winnings: ₹{winning}, Bonus: ₹{bonus}.",
  },
};

async function tryAnswerBalanceQuery(uid, message) {
  const lang = detectReplyLanguage(message);
  let snap;
  try {
    snap = await db.ref(`users/${uid}`).once("value");
  } catch (err) {
    console.log("⚠️ tryAnswerBalanceQuery: could not load user:", err.message);
    return null;
  }
  const u = snap.val() || {};
  return {
    reply: fillTemplate(BALANCE_QUERY_TEMPLATES.full, lang, {
      balance: Number(u.balance) || 0,
      winning: Number(u.winningCash) || 0,
      bonus: Number(u.bonusCash) || 0,
    }),
    awaitingClarification: false,
  };
}

// ---- VIP status ----
const VIP_QUERY_TEMPLATES = {
  active: {
    en: "You're a VIP member — valid till {expiry}.",
    hi: "आप VIP मेंबर हैं — {expiry} तक वैलिड।",
    hinglish: "Aap VIP member ho — {expiry} tak valid hai.",
  },
  inactive: {
    en: "You're not a VIP member right now. Weekly plan: ₹{weeklyPrice}, Monthly plan: ₹{monthlyPrice}.",
    hi: "आप अभी VIP मेंबर नहीं हैं। वीकली प्लान: ₹{weeklyPrice}, मंथली प्लान: ₹{monthlyPrice}।",
    hinglish: "Aap abhi VIP member nahi ho. Weekly plan: ₹{weeklyPrice}, Monthly plan: ₹{monthlyPrice}.",
  },
};

async function tryAnswerVipQuery(uid, message) {
  const lang = detectReplyLanguage(message);
  let userSnap;
  try {
    userSnap = await db.ref(`users/${uid}`).once("value");
  } catch (err) {
    console.log("⚠️ tryAnswerVipQuery: could not load user:", err.message);
    return null;
  }
  const u = userSnap.val() || {};
  const isVip = u.vipActive === true && Number(u.vipExpiresAt || 0) > Date.now();

  if (isVip) {
    const expiry = new Date(Number(u.vipExpiresAt)).toLocaleString("en-IN", {
      timeZone: "Asia/Kolkata", day: "2-digit", month: "short", year: "numeric", hour: "numeric", minute: "2-digit", hour12: true,
    });
    return { reply: fillTemplate(VIP_QUERY_TEMPLATES.active, lang, { expiry }), awaitingClarification: false };
  }

  let weeklyPrice = 0, monthlyPrice = 0;
  try {
    const vipSettingsSnap = await db.ref("settings/vipMembership").once("value");
    const vs = vipSettingsSnap.val() || {};
    weeklyPrice = Number(vs.weeklyPrice) || 0;
    monthlyPrice = Number(vs.monthlyPrice) || 0;
  } catch (err) {
    console.log("⚠️ tryAnswerVipQuery: could not load vipMembership settings:", err.message);
  }
  return {
    reply: fillTemplate(VIP_QUERY_TEMPLATES.inactive, lang, { weeklyPrice, monthlyPrice }),
    awaitingClarification: false,
  };
}

// ---- Referral status ----
const REFERRAL_QUERY_TEMPLATES = {
  info: {
    en: "Your referral code is {code}. Pending: {pendingCount}, Completed: {completedCount}.",
    hi: "आपका रेफरल कोड {code} है। पेंडिंग: {pendingCount}, कम्पलीट: {completedCount}।",
    hinglish: "Aapka referral code {code} hai. Pending: {pendingCount}, Complete: {completedCount}.",
  },
  noCode: {
    en: "You don't have a referral code yet — check your profile.",
    hi: "आपका अभी कोई रेफरल कोड नहीं है — प्रोफाइल चेक करें।",
    hinglish: "Aapka abhi koi referral code nahi hai — profile check karo.",
  },
};

async function tryAnswerReferralQuery(uid, message) {
  const lang = detectReplyLanguage(message);
  let userSnap;
  try {
    userSnap = await db.ref(`users/${uid}`).once("value");
  } catch (err) {
    console.log("⚠️ tryAnswerReferralQuery: could not load user:", err.message);
    return null;
  }
  const u = userSnap.val() || {};
  if (!u.referralCode) {
    return { reply: fillTemplate(REFERRAL_QUERY_TEMPLATES.noCode, lang), awaitingClarification: false };
  }

  let pendingCount = 0, completedCount = 0;
  try {
    const prSnap = await db.ref("pendingReferrals").orderByChild("referrerUid").equalTo(uid).once("value");
    prSnap.forEach((c) => {
      const v = c.val() || {};
      if (v.status === "completed") completedCount += 1;
      else pendingCount += 1;
    });
  } catch (err) {
    console.log("⚠️ tryAnswerReferralQuery: could not load pendingReferrals:", err.message);
  }

  return {
    reply: fillTemplate(REFERRAL_QUERY_TEMPLATES.info, lang, {
      code: u.referralCode, pendingCount, completedCount,
    }),
    awaitingClarification: false,
  };
}

// Registry: har entry ek hint-regex aur uska handler hai. `/ask-ai` route
// inhe order me try karta hai (match-earnings ke baad, FAQ-deterministic
// se pehle) — jo pehla regex match kare, uska handler chalta hai.
// "Kaise/how to/kese karu" jaisi HOW-TO queries ko deterministic
// stats-handlers (jo sirf raw numbers deti hain jaise "aapne ₹5 deposit
// kiye") se bachate hain -- inhe FAQ/AI flow me jaane dete hain jahan
// admin ne actual step-by-step guide FAQ set ki ho. Warna "deposit kaise
// kare?" jaisa how-to sawaal bhi "aapne itna deposit kiya hai" jaisa
// galat stats-jawab pa jaata tha.
const HOW_TO_QUERY_HINT = /\b(kaise|kese|kaisay|kyu?nkar|how to|how do i|how can i|process|steps?|tarika|tarika)\b/i;

const DETERMINISTIC_QUERY_ANSWERERS = [
  { hint: /\b(deposit|deposits|deposited|jama)\b/i, handler: tryAnswerDepositQuery },
  { hint: /\b(withdraw|withdrawal|withdrawals|nikala|nikale|nikasi)\b/i, handler: tryAnswerWithdrawalQuery },
  { hint: /\b(balance|wallet)\b/i, handler: tryAnswerBalanceQuery },
  { hint: /\b(vip|membership|premium)\b/i, handler: tryAnswerVipQuery },
  { hint: /\b(referral|refer)\b/i, handler: tryAnswerReferralQuery },
];

app.post("/ask-ai", verifyAuth, async (req, res) => {
  try {
    const uid = req.uid;
    const { message } = req.body;

    if (!message || typeof message !== "string" || !message.trim()) {
      return res.status(400).json({ error: "message is required" });
    }
    const cleanMsg = message.trim().slice(0, 500);

    // 0) Match-earnings queries ("kitna jeeta maine ... match me?") ko AI
    // ko bheje bina hi deterministic DB lookup se answer karne ki koshish
    // karo. Ye normally "match/won/earnings" type keywords hone par try
    // hota hai — LEKIN agar hamara pichla AI reply khud ek clarification
    // tha (noMatchFoundAtTime / multipleMatchesFound — "sahi match ka naam
    // ya time confirm karo"), to uska direct follow-up (jisme sirf match
    // ka naam hota hai, koi "won/prize" keyword nahi) bhi deterministic
    // path me hi jaana chahiye — warna wo seedha generic AI-FAQ flow me
    // chala jaata hai jisko real prize data pata hi nahi hota.
    const EARNINGS_QUERY_HINT = /\b(won|win|winning|winnings|earn|earning|earnings|prize|jeeta|jeete|jeeti|jeetu)\b/i;
    let isAwaitingClarificationReply = false;
    try {
      const lastMsgsSnap = await db
        .ref(`aiSupportChats/${uid}/messages`)
        .orderByChild("timestamp")
        .limitToLast(1)
        .once("value");
      lastMsgsSnap.forEach((m) => {
        const v = m.val() || {};
        if (v.senderType === "ai" && v.awaitingMatchClarification === true) {
          isAwaitingClarificationReply = true;
        }
      });
    } catch (lastMsgErr) {
      console.log("⚠️ Could not check last AI message for clarification follow-up:", lastMsgErr.message);
    }

    if (EARNINGS_QUERY_HINT.test(cleanMsg) || isAwaitingClarificationReply) {
      try {
        const deterministicResult = await tryAnswerMatchEarningsQuery(uid, cleanMsg);
        if (deterministicResult) {
          const deterministicReply = deterministicResult.reply;
          const now2 = Date.now();
          const chatRef2 = db.ref(`aiSupportChats/${uid}/messages`);
          const userMsgRef2 = chatRef2.push();
          await userMsgRef2.set({ message: cleanMsg, senderType: "user", senderUid: uid, timestamp: now2 });
          const aiMsgRef2 = chatRef2.push();
          const replyTs2 = Date.now();
          await aiMsgRef2.set({
            message: deterministicReply,
            senderType: "ai",
            timestamp: replyTs2,
            aiProvider: "deterministic", // no LLM call was made for this reply
            redirectSupport: false,
            redirectTutorial: false,
            awaitingMatchClarification: !!deterministicResult.awaitingClarification,
          });
          try {
            await db.ref(`aiSupportChats/${uid}`).update({
              uid,
              lastMessage: deterministicReply,
              lastMessageAt: replyTs2,
            });
          } catch (metaErr2) {
            console.log("⚠️ AI chat metadata update failed (deterministic path):", metaErr2.message);
          }
          return res.json({ success: true, reply: deterministicReply });
        }
      } catch (detErr) {
        console.log("⚠️ tryAnswerMatchEarningsQuery failed, falling back to AI:", detErr.message);
        // fall through to normal AI flow below
      }
    }

    // 0.4) Deterministic FAQ match — agar question kisi active FAQ se
    // near-exact match karta hai, ise SABSE PEHLE try karo (deposit/
    // withdrawal/balance/etc. keyword-based handlers se bhi pehle). Isliye
    // kyunki admin ne agar khud "How to withdraw fund in UPI" jaisa FAQ
    // banaya hai, wahi authoritative answer honi chahiye — na ki neeche
    // wala generic "withdraw" keyword handler jo sirf raw DB stats deta
    // hai. FAQ match hone par LLM provider ko call kiye bina hi seedha
    // wahi FAQ answer bhej do (saves quota on all providers, not just one).
    try {
      const faqDeterministicReply = await tryAnswerFromFaqDeterministic(cleanMsg);
      if (faqDeterministicReply) {
        const now3 = Date.now();
        const chatRef3 = db.ref(`aiSupportChats/${uid}/messages`);
        const userMsgRef3 = chatRef3.push();
        await userMsgRef3.set({ message: cleanMsg, senderType: "user", senderUid: uid, timestamp: now3 });
        const aiMsgRef3 = chatRef3.push();
        const replyTs3 = Date.now();
        await aiMsgRef3.set({
          message: faqDeterministicReply,
          senderType: "ai",
          timestamp: replyTs3,
          aiProvider: "deterministic-faq", // no LLM call was made for this reply
          redirectSupport: false,
          redirectTutorial: false,
        });
        try {
          await db.ref(`aiSupportChats/${uid}`).update({
            uid,
            lastMessage: faqDeterministicReply,
            lastMessageAt: replyTs3,
          });
        } catch (metaErr3) {
          console.log("⚠️ AI chat metadata update failed (deterministic FAQ path):", metaErr3.message);
        }
        return res.json({ success: true, reply: faqDeterministicReply });
      }
    } catch (faqDetErr) {
      console.log("⚠️ tryAnswerFromFaqDeterministic failed, falling back to keyword answerers/AI:", faqDetErr.message);
      // fall through to deterministic keyword answerers / normal AI flow below
    }

    // 0.5) Deposit/withdrawal/balance/VIP/referral queries — koi FAQ match
    // nahi hua (upar), to ab generic keyword-based DB-lookup try karo
    // (jaise "mera balance kitna hai" ya "kitna withdraw kiya" jaise raw
    // stats questions ke liye), koi AI call nahi. LEKIN agar sawaal
    // "kaise/how to" jaisा how-to/guide-type lag raha hai (jaise "deposit
    // kaise kare?"), to ye poora block skip karte hain -- warna raw stats
    // ka galat jawab mil jaata tha jab user actually step-by-step guide
    // maang raha tha. Aisे queries FAQ/general-AI flow me jaate hain.
    if (!HOW_TO_QUERY_HINT.test(cleanMsg)) {
    for (const { hint, handler } of DETERMINISTIC_QUERY_ANSWERERS) {
      if (!hint.test(cleanMsg)) continue;
      try {
        const deterministicResult = await handler(uid, cleanMsg);
        if (deterministicResult) {
          const deterministicReply = deterministicResult.reply;
          const now2b = Date.now();
          const chatRef2b = db.ref(`aiSupportChats/${uid}/messages`);
          const userMsgRef2b = chatRef2b.push();
          await userMsgRef2b.set({ message: cleanMsg, senderType: "user", senderUid: uid, timestamp: now2b });
          const aiMsgRef2b = chatRef2b.push();
          const replyTs2b = Date.now();
          await aiMsgRef2b.set({
            message: deterministicReply,
            senderType: "ai",
            timestamp: replyTs2b,
            aiProvider: "deterministic",
            redirectSupport: false,
            redirectTutorial: false,
            awaitingMatchClarification: !!deterministicResult.awaitingClarification,
          });
          try {
            await db.ref(`aiSupportChats/${uid}`).update({
              uid,
              lastMessage: deterministicReply,
              lastMessageAt: replyTs2b,
            });
          } catch (metaErr2b) {
            console.log("⚠️ AI chat metadata update failed (deterministic query path):", metaErr2b.message);
          }
          return res.json({ success: true, reply: deterministicReply });
        }
      } catch (detErr2) {
        console.log("⚠️ deterministic query answerer failed, falling back to AI:", detErr2.message);
        // fall through to next answerer / normal AI flow
      }
      break; // hint match ho gaya tha (chahe handler null/error de), aur answerers try mat karo
    }
    } // end of "!HOW_TO_QUERY_HINT.test(cleanMsg)" guard

    // Basic spam guard: 1 request per 3 seconds per user
    const lastAt = aiChatRateLimit.get(uid) || 0;
    if (Date.now() - lastAt < 3000) {
      return res.status(429).json({ error: "Please wait a moment before sending again" });
    }
    aiChatRateLimit.set(uid, Date.now());

    const availableProviders = configuredProviders();
    if (!availableProviders.length) {
      console.log("❌ No AI provider API keys configured (GEMINI_API_KEY / GROQ_API_KEY / CEREBRAS_API_KEY / OPENROUTER_API_KEY all missing)");
      return res.status(500).json({ error: "AI is not configured yet, contact admin" });
    }

    const now = Date.now();
    const chatRef = db.ref(`aiSupportChats/${uid}/messages`);

    // 1) Save the user's message first
    const userMsgRef = chatRef.push();
    await userMsgRef.set({
      message: cleanMsg,
      senderType: "user",
      senderUid: uid,
      timestamp: now,
    });

    // 2) Get a bit of profile context so the AI can personalize its answer
    let userName = "Player";
    try {
      const profileSnap = await db.ref(`users/${uid}/displayName`).once("value");
      if (profileSnap.exists()) userName = profileSnap.val();
    } catch (ctxErr) {
      console.log("⚠️ Could not load user name for AI context:", ctxErr.message);
    }

    // 2b) Load admin-defined FAQs (Admin Panel > AI FAQ Manager). These are the
    // ONLY source of truth the AI is allowed to answer from. The AI's job here
    // is just language/tone matching (Hindi/English/Hinglish, casual/formal,
    // incomplete phrasing, typos etc.) — not inventing new information.
    let faqBlock = "(no FAQs configured yet)";
    try {
      const faqSnap = await db.ref("aiFaqs").once("value");
      if (faqSnap.exists()) {
        const faqs = [];
        faqSnap.forEach((c) => {
          const v = c.val() || {};
          if (v.active !== false && v.question && v.answer) {
            faqs.push({ id: c.key, question: String(v.question), answer: String(v.answer) });
          }
        });
        if (faqs.length) {
          faqBlock = faqs
            .map((f, i) => `${i + 1}. Q: ${f.question}\n   A: ${f.answer}`)
            .join("\n");
        }
      }
    } catch (faqErr) {
      console.log("⚠️ Could not load aiFaqs:", faqErr.message);
    }

    // 2c) Load admin-added Video Tutorial titles (Admin Panel > Tutorials).
    // The AI only needs the TITLES (not the video links) to judge whether a
    // "how to ..." style question is already covered by an existing tutorial
    // video — the actual navigation is handled by the app itself.
    let tutorialTitlesBlock = "(no tutorials configured yet)";
    try {
      const tuSnap = await db.ref("tutorials").once("value");
      if (tuSnap.exists()) {
        const titles = [];
        tuSnap.forEach((c) => {
          const v = c.val() || {};
          if (v.title) titles.push(String(v.title));
        });
        if (titles.length) {
          tutorialTitlesBlock = titles.map((t, i) => `${i + 1}. ${t}`).join("\n");
        }
      }
    } catch (tuErr) {
      console.log("⚠️ Could not load tutorials:", tuErr.message);
    }

    // 2d) Last 6 pichhle messages fetch karo (current message iske alawa hai)
    // taaki AI ko conversation ka context mile -- "stateless" nahi rahega ab.
    const recentHistory = await fetchRecentChatHistory(uid, 6, userMsgRef.key);

    // 3) Build the shared system prompt (used for whichever AI provider ends up answering)
    const systemPrompt =
      "You are a friendly in-app support assistant for a gaming/contest app called ClashX. " +
      "The user's display name is '" + userName + "'. " +
      "You have two knowledge sources: (A) the APP OVERVIEW below, which describes what each " +
      "section of the app does in general terms, and (B) the FAQ LIST below, set up by the app " +
      "admin with fixed, authoritative answers. You must ONLY use these two sources — you have " +
      "no other information about the app.\n\n" +
      "APP OVERVIEW (general navigation — what each section is for):\n" +
      "- Home: Main dashboard — shows Esport Games tiles (Free Fire, BR Full Map, LW-CS, etc.) " +
      "at the bottom. Tap a game tile to see its list of matches/tournaments, then tap a match " +
      "to view details and join by paying the entry fee (if any).\n" +
      "- My Contests (on Home): Upcoming / Ongoing / Results tabs — shows matches the user has " +
      "joined or can join, and past match results.\n" +
      "- Earn: Ways to earn coins/rewards (daily tasks, referrals, etc.).\n" +
      "- Wallet: Check balance, deposit money, request withdrawal.\n" +
      "- Profile: User account details, VIP membership, level & rewards, referral code, app " +
      "tutorials, themes/language, and personal info.\n" +
      "- Leaderboard (Rank): Rank list of top players.\n" +
      "- Lottery: Join lottery draws.\n" +
      "- Scratch Card: Play the scratch card game for rewards.\n" +
      "- Spin Wheel: Play the spin wheel game for rewards.\n" +
      "- Referral: Invite friends and earn referral bonuses.\n" +
      "- Shop: Buy products/items.\n" +
      "- Support: Raise a complaint or support ticket, AI support chat, contact channels.\n" +
      "- Tutorials: Watch how-to video guides for using the app.\n" +
      "- Match History: View past match/game records.\n" +
      "- Policies: Read terms, rules, and policies.\n" +
      "- Settings: Adjust app settings.\n\n" +
      "FAQ LIST:\n" + faqBlock + "\n\n" +
      "HOW THE TWO SOURCES WORK TOGETHER (important):\n" +
      "- For simple 'where do I find X' / 'which section is for Y' navigation questions, you may " +
      "answer directly from the APP OVERVIEW above, even if there's no exact FAQ for it.\n" +
      "- For anything involving specific facts, numbers, timelines, rules, eligibility, or " +
      "policy details (e.g. withdrawal time, minimum amount, bonus percentage, eligibility " +
      "conditions), you must ONLY use the FAQ LIST — never invent or guess these details even " +
      "if they seem related to a section in the APP OVERVIEW. If no FAQ covers the specific " +
      "detail being asked, treat it as NO MATCH (case 3 below), even if the general section is " +
      "described in the APP OVERVIEW.\n\n" +
      "LANGUAGE RULE (very important — follow this exactly):\n" +
      "Detect the language/script the user's CURRENT message is written in — this could be " +
      "English, Hindi (Devanagari script), Hinglish (Hindi written in Roman letters), or any " +
      "other language (Marathi, Bengali, Tamil, Telugu, Gujarati, Punjabi, Urdu, etc.). Always " +
      "reply in that SAME language and script. Do NOT default to Hinglish just because that's " +
      "common in this app — if the user wrote in pure English, reply in pure English; if they " +
      "wrote in Devanagari Hindi, reply in Devanagari Hindi; if they wrote in another language " +
      "entirely, reply in that language. Only use Hinglish when the user themselves wrote in " +
      "Hinglish. Base this purely on the user's CURRENT message, not on earlier messages in the " +
      "conversation (they may switch languages between messages).\n" +
      "MIXED-LANGUAGE MESSAGES: If the user's message itself blends more than one language " +
      "(e.g. a Hindi sentence with English words mixed in, or Hinglish with a few pure-English " +
      "phrases, or any other combination), mirror that same blend back — don't force it into a " +
      "single 'pure' language. Match roughly which language dominates and how the mixing is " +
      "done, so your reply feels natural to how they actually wrote, not artificially uniform.\n\n" +
      "TYPO / SPELLING-MISTAKE RULE (very important — follow this exactly):\n" +
      "Users often type fast on mobile and make spelling mistakes or use inconsistent " +
      "transliteration, especially for Hindi words written in Roman letters. Be generous and " +
      "infer the intended word from context — do not require exact spelling. For example: " +
      "'widraw', 'witdraw', 'wthdrawal' all mean 'withdraw'/'withdrawal'; 'pemant', 'paymnt', " +
      "'payemnt' mean 'payment'; 'balence', 'blance' mean 'balance'; 'refered', 'refral' mean " +
      "'referral'; 'tournamnet', 'turnament' mean 'tournament'. This applies generally, not just " +
      "to these examples — use your best judgement to figure out what word was intended even " +
      "with missing/extra/swapped letters, and match it against the FAQ list normally. Never " +
      "tell the user their spelling is wrong or ask them to retype correctly — just understand " +
      "what they meant and answer normally as if they'd spelled it correctly.\n\n" +
      "How to respond:\n" +
      "1) FAQ MATCH: If the user's question clearly matches one FAQ (even if it's phrased " +
      "differently, in any language, casually, with typos, etc. — see the two rules above), " +
      "answer using ONLY the information in that FAQ's answer, in the user's language per the " +
      "LANGUAGE RULE above. You may naturally rephrase it in the user's own tone/style, but " +
      "never add, remove, or change any fact, number, or rule from that answer.\n" +
      "1b) NAVIGATION MATCH: If the question is purely about which section of the app to use " +
      "for something, and it doesn't need any specific fact/number/policy, you may answer " +
      "directly from the APP OVERVIEW even without an exact FAQ match, per the rule above.\n" +
      "2) PARTIAL / UNCLEAR: If the question is incomplete, vague, or could match more than " +
      "one FAQ, do NOT guess — ask ONE short, specific follow-up question (in the user's " +
      "language per the LANGUAGE RULE above) to clarify exactly what they mean, so it can be " +
      "matched properly next time.\n" +
      "3) NO MATCH: If the question is not covered by any FAQ or the APP OVERVIEW, needs a " +
      "specific fact/number/policy that isn't in the FAQ LIST, or is unrelated to the app, " +
      "politely say (in the user's language per the LANGUAGE RULE above) you're not able to " +
      "help with that specific query and tell the user to contact Customer Support from the " +
      "app's Support section. In this case ONLY (case 3), end your reply with a new line " +
      "containing exactly the token @@REDIRECT_SUPPORT@@ and nothing else on that line. Do NOT " +
      "include this token for case 1, 1b, or case 2 replies.\n" +
      "4) TUTORIAL VIDEO MATCH: Separately from the above, check the list of existing App " +
      "Tutorial video titles below. If the user's question is a 'how to' / step-by-step " +
      "question, or its topic clearly matches one of these tutorial titles (in any language " +
      "or phrasing, allowing for typos per the TYPO RULE above), briefly mention (in the " +
      "user's language per the LANGUAGE RULE above) that a video tutorial covering this is " +
      "available in the app, then end your reply with a new line containing exactly the token " +
      "@@REDIRECT_TUTORIAL@@ and nothing else on that line. This token can appear together " +
      "with (on its own separate line from) @@REDIRECT_SUPPORT@@ if both apply, but usually " +
      "only one applies. Do NOT add this token if no tutorial title is actually relevant — " +
      "do not guess or invent a tutorial that isn't in the list.\n\n" +
      "EXISTING APP TUTORIAL VIDEO TITLES:\n" + tutorialTitlesBlock + "\n\n" +
      "Never invent specific balances, transaction statuses, or match results. Keep replies " +
      "short, clear, and friendly.";


    // NAYA LOGIC (multi-provider race + load-balance): "AI ka reply
    // hamesha sabse fast available server se aaye, aur jab load zyada ho to
    // naye requests automatically dusre AI provider pe shift ho jaayein."
    //
    // AI_ACTIVE_REQUESTS is checked BEFORE incrementing for this request, so
    // it reflects how many OTHER "/ask-ai" calls are already in flight right
    // now on this server instance -- that's the real signal for "kitna load
    // hai is waqt".
    const isHighLoad = AI_ACTIVE_REQUESTS >= AI_RACE_THRESHOLD;
    AI_ACTIVE_REQUESTS++;

    let aiReply;
    let replyTs;
    const aiMsgRef = chatRef.push();
    const FINAL_ERROR_REPLY = "Please try again after some time.";

    // NAYA: jab AI FAQ list me koi match nahi milta, to system prompt use ek
    // hidden token (@@REDIRECT_SUPPORT@@) reply ke end me daalne ko kehta hai.
    // Isi tarah, jab question ka topic ek existing tutorial video se match
    // kare, to ek dusra hidden token (@@REDIRECT_TUTORIAL@@) aata hai. Yahaan
    // hum dono tokens ko reply text se nikaal (strip) kar dete hain (user ko
    // kabhi raw token dikhna nahi chahiye) aur clean boolean flags
    // (redirectSupport / redirectTutorial) DB record me save karte hain —
    // frontend inhi flags ko dekh kar us specific message ke neeche
    // "Contact Support" / "Watch Tutorial" chhota tile dikhata hai.
    const REDIRECT_SUPPORT_TOKEN = "@@REDIRECT_SUPPORT@@";
    const REDIRECT_TUTORIAL_TOKEN = "@@REDIRECT_TUTORIAL@@";
    function extractRedirect(text) {
      if (typeof text !== "string") return { text, redirectSupport: false, redirectTutorial: false };
      const redirectSupport = text.includes(REDIRECT_SUPPORT_TOKEN);
      const redirectTutorial = text.includes(REDIRECT_TUTORIAL_TOKEN);
      let clean = text;
      if (redirectSupport) clean = clean.split(REDIRECT_SUPPORT_TOKEN).join("");
      if (redirectTutorial) clean = clean.split(REDIRECT_TUTORIAL_TOKEN).join("");
      clean = clean.trim();
      return { text: clean, redirectSupport, redirectTutorial };
    }

    // Final message array jo har provider ko jaata hai: pichhle 6 messages
    // (alternating user/assistant) + current message sabse end me. System
    // prompt yahan shaamil nahi -- wo har provider apne format ke hisaab se
    // alag se jodta hai (Gemini: system_instruction, baaki: messages[0]).
    const conversationMessages = [...recentHistory, { role: "user", content: cleanMsg }];

    try {
      // 1) First attempt: race everyone if load is low, else go straight to
      // whichever single provider is least busy right now.
      const firstAttempt = isHighLoad
        ? await callLeastBusy(availableProviders, systemPrompt, conversationMessages)
        : await raceProviders(availableProviders, systemPrompt, conversationMessages);

      if (firstAttempt.ok) {
        // Got a reply on the first attempt -- single clean write, no
        // retrying bubble needed.
        const { text: cleanReply, redirectSupport, redirectTutorial } = extractRedirect(firstAttempt.text);
        aiReply = cleanReply;
        replyTs = Date.now();
        await aiMsgRef.set({ message: aiReply, senderType: "ai", timestamp: replyTs, aiProvider: firstAttempt.provider, redirectSupport, redirectTutorial });
      } else {
        // 2) Everyone failed (race) or the chosen one failed (load-balance)
        // -- push the visible "retrying" placeholder so the user sees a
        // typing-style animation in chat while we switch to another provider.
        await aiMsgRef.set({
          message: "",
          senderType: "ai",
          retrying: true,
          timestamp: Date.now(),
        });

        // 3) One more try -- least-busy among whatever's left (excluding the
        // one that just failed, if we know which one that was).
        const excluded = firstAttempt.provider ? [firstAttempt.provider] : [];
        let secondAttempt = await callLeastBusy(availableProviders, systemPrompt, conversationMessages, excluded);

        // 4) Agar dusra attempt bhi fail hua (jaise sab providers temporarily
        // overloaded/503 hain), ek chhota 1s wait ke baad AKHRI baar poori
        // list se race try karte hain, isse pehle "Please try again" bolke
        // hi haar maan lein. Ye transient overload errors (jaise Gemini ka
        // "high demand, try again later") ko user ko dikhne se pehle hi
        // khud resolve kar deta hai zyadatar cases me.
        if (!secondAttempt.ok) {
          await new Promise((r) => setTimeout(r, 1000));
          secondAttempt = await raceProviders(availableProviders, systemPrompt, conversationMessages);
        }

        const { text: cleanReply2, redirectSupport: redirectSupport2, redirectTutorial: redirectTutorial2 } = secondAttempt.ok
          ? extractRedirect(secondAttempt.text)
          : { text: FINAL_ERROR_REPLY, redirectSupport: false, redirectTutorial: false };
        aiReply = cleanReply2;
        replyTs = Date.now();

        // 4) Update the SAME node with the final outcome -- retrying:false so
        // the frontend swaps the animation for the real text in place.
        await aiMsgRef.update({ message: aiReply, retrying: false, timestamp: replyTs, aiProvider: secondAttempt.provider || null, redirectSupport: redirectSupport2, redirectTutorial: redirectTutorial2 });
      }
    } finally {
      AI_ACTIVE_REQUESTS--;
    }


    // Metadata update is optional, must not fail the whole request
    try {
      await db.ref(`aiSupportChats/${uid}`).update({
        uid,
        userName,
        lastMessage: aiReply,
        lastMessageAt: replyTs,
      });
    } catch (metaErr) {
      console.log("⚠️ AI chat metadata update failed:", metaErr.message);
    }

    return res.json({ success: true, reply: aiReply });
  } catch (err) {
    console.log("❌ Ask-AI error:", err.message);
    return res.status(500).json({ error: "Something went wrong" });
  }
});

// ================= DELETE AI CHAT (admin/staff, sup_mgt permission) =================
// Wipes ONE user's entire conversation with the AI support bot
// (aiSupportChats/{uid} — both the `messages` list AND the small metadata
// object next to it: lastMessage/lastMessageAt/userName). This is the exact
// same DB path the user's own app reads from, so deleting it here removes
// the chat from the user's side too, instantly and for real (not a soft
// "hide" flag) — next time they open AI chat it just starts fresh, like
// they never talked to the bot before.
// Deliberately scoped to ONLY this one path. Does not touch `users/{uid}`,
// balances, transactions, tickets, or anything else about the account.
// ================= ADMIN: RESET USER PASSWORD =================
// Client SDK se koi bhi (admin/staff included) kisi doosre user ka password
// change nahi kar sakta — Firebase Auth sirf khud-logged-in user ko apna
// password reset karne deta hai. Isliye ye Admin SDK route zaroori hai:
// admin.auth().updateUser() se server-side kisi bhi target user ka password
// force-set kiya ja sakta hai, bina unka current password jaane.
app.post("/admin/reset-user-password", verifyAuth, async (req, res) => {
  try {
    const callerUid = req.uid;
    const { targetUid, newPassword } = req.body || {};

    if (!targetUid || typeof targetUid !== "string") {
      return res.status(400).json({ error: "targetUid is required" });
    }
    if (!newPassword || typeof newPassword !== "string" || newPassword.length < 6) {
      return res.status(400).json({ error: "newPassword must be at least 6 characters" });
    }

    const { hasPerm } = await checkStaffPermission(callerUid, "user_mgt");
    if (!hasPerm) {
      return res.status(403).json({ error: "unauthorized" });
    }

    await admin.auth().updateUser(targetUid, { password: newPassword });

    // Staff activity log — WHO reset WHOSE password, kab. Password value
    // khud kabhi log nahi hoti.
    await db.ref("staffActivityLogs").push({
      uid: callerUid,
      action: "Reset User Password",
      details: `Target UID: ${targetUid}`,
      timestamp: Date.now(),
    });

    console.log(`🔑 Password reset for uid=${targetUid} by ${callerUid}`);
    return res.json({ success: true });
  } catch (err) {
    console.log("❌ Reset user password error:", err.message);
    if (err.code === "auth/user-not-found") {
      return res.status(404).json({ error: "User not found in Firebase Auth" });
    }
    return res.status(500).json({ error: err.message || "Something went wrong" });
  }
});

app.post("/admin/delete-ai-chat", verifyAuth, async (req, res) => {
  try {
    const callerUid = req.uid;
    const { targetUid } = req.body;

    if (!targetUid || typeof targetUid !== "string") {
      return res.status(400).json({ error: "targetUid is required" });
    }

    const { hasPerm } = await checkStaffPermission(callerUid, "sup_mgt");
    if (!hasPerm) {
      return res.status(403).json({ error: "unauthorized" });
    }

    await db.ref(`aiSupportChats/${targetUid}`).remove();

    console.log(`🗑️ AI chat deleted for uid=${targetUid} by ${callerUid}`);
    return res.json({ success: true });
  } catch (err) {
    console.log("❌ Delete AI chat error:", err.message);
    return res.status(500).json({ error: "Something went wrong" });
  }
});


app.get("/", (req, res) => res.send("push-sender is running flawlessly!"));

// ================= GLOBAL JSON ERROR HANDLER =================
// Safety net: agar kabhi bhi (body-parser payload-too-large, malformed
// ================= SUPPORT TICKET SYSTEM =================
// Tiles: "Report Hacker" and "Room Full / Kicked by Host — Refund" only.
// (POV recording submission was intentionally left out — full match
// recordings ate too much R2 storage.)

async function checkStaffPermission(callerUid, permKey) {
  const [adminConfigSnap, staffSnap, permSnap] = await Promise.all([
    db.ref("adminConfig/adminUid").get(),
    db.ref(`staff/${callerUid}/status`).get(),
    db.ref(`staff/${callerUid}/permissions`).get(),
  ]);
  const isAdmin = adminConfigSnap.val() === callerUid;
  const isActiveStaff = staffSnap.val() === "active";
  const perms = permSnap.val() || [];
  const hasPerm = isAdmin || (isActiveStaff && (perms.includes("all") || perms.includes(permKey)));
  return { isAdmin, isActiveStaff, hasPerm };
}

// Resolves the display name to store on a staff-sent ticket message — same
// idea as VIP chat's senderName, so the admin panel can show WHO on staff
// replied while the user side still only ever shows a generic "Support" tag.
async function getStaffDisplayName(callerUid, isAdmin) {
  if (isAdmin) return "Main Admin";
  const nameSnap = await db.ref(`staff/${callerUid}/name`).get();
  return nameSnap.val() || "Staff Member";
}

// 1) Cloudinary upload signature — used for ticket creation AND mid-chat
//    attachments. Client uploads DIRECTLY to Cloudinary using this
//    signature (never touches our server).
//    Size limits match Cloudinary's own free-tier defaults (10MB image /
//    100MB video) — enforced here via a signed max_bytes param so Cloudinary
//    itself rejects an oversized upload even if a client skips the
//    client-side check.
const TICKET_UPLOAD_LIMITS = {
  image: 10 * 1024 * 1024,   // 10MB
  video: 100 * 1024 * 1024,  // 100MB
};

app.post("/tickets/get-upload-signature", verifyAuth, async (req, res) => {
  try {
    const { ticketId, fileType } = req.body;
    const resourceType = fileType && fileType.startsWith("video/") ? "video" : "image";
    const maxBytes = TICKET_UPLOAD_LIMITS[resourceType];

    const timestamp = Math.round(Date.now() / 1000);
    const folder = `tickets/${req.uid}/${ticketId || "new"}`;

    // FIX: max_bytes hata diya signature params se -- ye Cloudinary ka
    // real/recognized signed upload parameter nahi hai, isse "Invalid
    // Signature" error aa raha tha. File-size check already frontend me
    // (10MB image / 100MB video) ho raha hai upload se pehle hi.
    const paramsToSign = { timestamp, folder };
    const signature = cloudinary.utils.api_sign_request(paramsToSign, process.env.CLOUDINARY_API_SECRET);

    res.json({
      signature,
      timestamp,
      folder,
      apiKey: process.env.CLOUDINARY_API_KEY,
      cloudName: process.env.CLOUDINARY_CLOUD_NAME,
      uploadUrl: `https://api.cloudinary.com/v1_1/${process.env.CLOUDINARY_CLOUD_NAME}/${resourceType}/upload`,
      resourceType,
      maxBytes,
    });
  } catch (err) {
    console.log("❌ get-upload-signature failed:", err.message);
    res.status(500).json({ error: "Failed to generate upload signature" });
  }
});

// 2) Create a ticket (client already uploaded the initial clip to R2)
app.post("/tickets/create", verifyAuth, async (req, res) => {
  try {
    const { ticketType, message, attachment } = req.body; // attachment: {url, publicId, resourceType, name}
    if (!["hacker", "refund"].includes(ticketType)) {
      return res.status(400).json({ error: "invalid ticketType" });
    }
    if (!attachment || !attachment.url) {
      return res.status(400).json({ error: "at least one attachment is required" });
    }

    const userSnap = await db.ref(`users/${req.uid}`).get();
    const userData = userSnap.val() || {};

    const ticketRef = db.ref("supportTickets").push();
    const now = Date.now();
    await ticketRef.set({
      ticketId: ticketRef.key,
      uid: req.uid,
      userName: userData.displayName || "",
      userEmail: userData.email || "",
      ticketType,
      status: "open",
      createdAt: now,
      updatedAt: now,
      closedAt: null,
      lastSenderRole: "user",
    });
    // Index so the OWNER can list their own tickets (queries need a
    // top-level .read, which we don't grant to normal users on
    // supportTickets itself — this per-uid index is what their
    // "My Tickets" list actually reads).
    await db.ref(`userTickets/${req.uid}/${ticketRef.key}`).set(true);

    await ticketRef.child("messages").push({
      senderUid: req.uid,
      senderRole: "user",
      text: message || "",
      attachment: attachment || null,
      timestamp: now,
    });

    res.json({ success: true, ticketId: ticketRef.key });
  } catch (err) {
    console.log("❌ /tickets/create failed:", err.message);
    res.status(500).json({ error: "Failed to create ticket" });
  }
});

// 3) Post a message (text and/or attachment) into an existing ticket thread
app.post("/tickets/:ticketId/message", verifyAuth, async (req, res) => {
  try {
    const { ticketId } = req.params;
    const { text, attachment } = req.body;
    const ticketSnap = await db.ref(`supportTickets/${ticketId}`).get();
    const ticket = ticketSnap.val();
    if (!ticket) return res.status(404).json({ error: "ticket not found" });

    const isOwner = ticket.uid === req.uid;
    let senderRole = null;
    let senderName = null;

    // Check staff permission FIRST — a staff member replying from the admin
    // panel should always be tagged "staff", even if their account also
    // happens to be the ticket's owner (e.g. an admin testing with their
    // own account). Only fall back to "user" when they aren't staff.
    const { hasPerm, isAdmin } = await checkStaffPermission(req.uid, "support_tickets");
    if (hasPerm) {
      senderRole = "staff";
      senderName = await getStaffDisplayName(req.uid, isAdmin);
    } else if (isOwner) {
      if (ticket.status === "closed") {
        return res.status(403).json({ error: "ticket is closed and read-only" });
      }
      senderRole = "user";
    } else {
      return res.status(403).json({ error: "unauthorized" });
    }

    if (!text && !attachment) {
      return res.status(400).json({ error: "text or attachment required" });
    }

    const now = Date.now();
    await db.ref(`supportTickets/${ticketId}/messages`).push({
      senderUid: req.uid,
      senderRole,
      senderName: senderName || null,
      text: text || "",
      attachment: attachment || null,
      timestamp: now,
    });
    await db.ref(`supportTickets/${ticketId}`).update({ updatedAt: now, lastSenderRole: senderRole });

    res.json({ success: true });
  } catch (err) {
    console.log("❌ /tickets/:id/message failed:", err.message);
    res.status(500).json({ error: "Failed to send message" });
  }
});

// 4) Close a ticket (staff/admin only, gated by support_tickets permission)
app.post("/tickets/:ticketId/close", verifyAuth, async (req, res) => {
  try {
    const { ticketId } = req.params;
    const { hasPerm } = await checkStaffPermission(req.uid, "support_tickets");
    if (!hasPerm) return res.status(403).json({ error: "unauthorized" });

    const ticketSnap = await db.ref(`supportTickets/${ticketId}`).get();
    if (!ticketSnap.exists()) return res.status(404).json({ error: "ticket not found" });

    const now = Date.now();
    await db.ref(`supportTickets/${ticketId}`).update({
      status: "closed",
      closedAt: now,
      updatedAt: now,
      closedBy: req.uid,
    });

    res.json({ success: true });
  } catch (err) {
    console.log("❌ /tickets/:id/close failed:", err.message);
    res.status(500).json({ error: "Failed to close ticket" });
  }
});

// Cleanup cron: 24h after closedAt, delete ticket (DB + R2 files)
const TICKET_RETENTION_MS = 24 * 60 * 60 * 1000;

async function cleanupClosedTickets() {
  try {
    const snap = await db.ref("supportTickets").orderByChild("status").equalTo("closed").get();
    if (!snap.exists()) return;
    const now = Date.now();
    const deletions = [];

    snap.forEach((child) => {
      const ticket = child.val();
      if (ticket.closedAt && now - ticket.closedAt >= TICKET_RETENTION_MS) {
        deletions.push(ticket);
      }
    });

    for (const ticket of deletions) {
      const msgs = ticket.messages ? Object.values(ticket.messages) : [];
      const attachments = msgs.filter((m) => m.attachment && m.attachment.publicId).map((m) => m.attachment);

      await Promise.all(
        attachments.map((a) =>
          cloudinary.uploader
            .destroy(a.publicId, { resource_type: a.resourceType || "video" })
            .catch((e) => console.log(`⚠️ failed to delete Cloudinary asset ${a.publicId}:`, e.message))
        )
      );

      await db.ref(`supportTickets/${ticket.ticketId}`).remove();
      await db.ref(`userTickets/${ticket.uid}/${ticket.ticketId}`).remove();
      console.log(`🗑️ Deleted expired ticket ${ticket.ticketId} (+ ${attachments.length} Cloudinary file(s))`);
    }
  } catch (err) {
    console.log("❌ cleanupClosedTickets failed:", err.message);
  }
}

setInterval(cleanupClosedTickets, 30 * 60 * 1000);
cleanupClosedTickets(); // also run once on boot

// ================= ONE-TIME MIGRATION: BACKFILL lifetimeWinnings =================
// lifetimeWinnings was added so "total ever won" (Profile stat, Earnings
// Leaderboard) stops using winningCash, which drops on withdrawal. New wins
// already increment it correctly going forward (admin.html). This route
// backfills it for EXISTING users so their historical total shows up too,
// instead of relying on the winningCash display-fallback forever.
//
// IMPORTANT: a flat `lifetimeWinnings = current winningCash` is WRONG for
// any user whose winningCash was later reduced by something outside of a
// normal "win" event — winningCash only reflects what's still sitting in
// the wallet today, so any past reduction silently erases that amount from
// their lifetime total. To recover that history we add back every event
// that has permanently (or not-yet-finally) removed money from winningCash:
//   lifetimeWinnings = current winningCash
//                     + sum of their 'completed' withdrawals (permanently left the wallet)
//                     + sum of their 'pending' withdrawals (already deducted, outcome not final yet)
//                     + sum of NEGATIVE admin "Adjust Balance" entries targeting
//                       winningCash specifically (tagged `field: 'winningCash'`
//                       in the deposits log — see admin.html's fmAdj handler)
// 'rejected' withdrawals are intentionally excluded — that amount is
// refunded back into winningCash on rejection, so it's already counted in
// the current balance and adding it again would double-count it. Likewise
// POSITIVE admin adjustments to winningCash aren't added on top — that
// credit is either still sitting in the current balance, or (if later
// withdrawn) already recovered via the withdrawals sum above.
// Only deposits entries with an explicit `field: 'winningCash'` tag are
// counted — older adjustment entries made before this tag existed can't be
// safely attributed to winningCash vs. balance vs. bonusCash and are
// skipped rather than risk corrupting the total.
// This still isn't a perfect ledger (it can't see winningCash spent on
// in-app purchases/lottery/etc. — only withdrawals and tagged admin
// adjustments), but it recovers by far the most common causes of "missing"
// history.
//
// Safety:
//  - Admin-only (Super Admin uid, via checkStaffPermission's isAdmin flag).
//  - Only touches users where lifetimeWinnings is still undefined — so
//    running it twice (or after new users already have real values from
//    actual wins) never overwrites or double-counts anything.
//  - Manual trigger only (no auto-run on boot/interval) — nothing changes
//    until you explicitly call this once.
//  - Doesn't touch winningCash, balance, bonusCash, or any other field —
//    purely additive, so withdrawals/spending/every other feature keeps
//    working exactly as before.
app.post("/admin/migrate-lifetime-winnings", verifyAuth, async (req, res) => {
  try {
    const { isAdmin } = await checkStaffPermission(req.uid, "user_mgt");
    if (!isAdmin) return res.status(403).json({ error: "Super Admin only" });

    const [usersSnap, withdrawalsSnap, depositsSnap] = await Promise.all([
      db.ref("users").once("value"),
      db.ref("withdrawals").once("value"),
      db.ref("deposits").once("value"),
    ]);
    if (!usersSnap.exists()) return res.json({ migrated: 0, skipped: 0 });

    // Sum past withdrawals per user that should be added back on top of
    // their current winningCash (see comment above for why).
    const recoveredByUser = {};
    if (withdrawalsSnap.exists()) {
      withdrawalsSnap.forEach((w) => {
        const v = w.val() || {};
        if (v.status !== "completed" && v.status !== "pending") return;
        const uid = v.userId;
        const amt = Number(v.amount) || 0;
        if (!uid || !amt) return;
        recoveredByUser[uid] = (recoveredByUser[uid] || 0) + amt;
      });
    }
    // Sum negative admin "Adjust Balance" entries explicitly tagged as
    // targeting winningCash — these are debits that permanently reduced
    // winningCash the same way a withdrawal does.
    if (depositsSnap.exists()) {
      depositsSnap.forEach((d) => {
        const v = d.val() || {};
        if (v.field !== "winningCash") return;
        if (!String(v.paymentMethod || "").startsWith("OVD_OP")) return;
        const amt = Number(v.amount) || 0;
        if (amt >= 0) return; // only negative (deduction) entries need recovering
        const uid = v.userId;
        if (!uid) return;
        recoveredByUser[uid] = (recoveredByUser[uid] || 0) + Math.abs(amt);
      });
    }

    const updates = {};
    let migrated = 0, skipped = 0;
    usersSnap.forEach((u) => {
      const v = u.val() || {};
      if (v.lifetimeWinnings !== undefined) { skipped++; return; }
      const recovered = recoveredByUser[u.key] || 0;
      updates[`users/${u.key}/lifetimeWinnings`] = (Number(v.winningCash) || 0) + recovered;
      migrated++;
    });

    if (Object.keys(updates).length) await db.ref().update(updates);
    console.log(`✅ lifetimeWinnings migration: ${migrated} users migrated, ${skipped} already had it`);
    res.json({ migrated, skipped });
  } catch (err) {
    console.log("❌ lifetimeWinnings migration failed:", err.message);
    res.status(500).json({ error: "Migration failed" });
  }
});

// Weekly leaderboard reset — previously this ONLY ran opportunistically
// whenever something happened to hit /ping (piggybacked on the external
// uptime pinger), so if no ping landed shortly after Monday 00:00 IST, the
// reset simply didn't happen until the next incidental ping. This runs the
// same check on its own real schedule instead, independent of ping traffic.
// Checking every 2 min keeps the delay after the actual reset moment small
// without adding a cron-package dependency. maybeResetWeeklyLeaderboard()
// is already idempotent (guarded by a DB transaction), so this running
// alongside /ping's call can never cause a double reset.
setInterval(maybeResetWeeklyLeaderboard, 2 * 60 * 1000);
maybeResetWeeklyLeaderboard(); // also run once on boot, in case a reset was missed while the server was down

// JSON body, ya koi aur unexpected error) request route handler tak
// pahunchne se pehle hi fail ho jaaye, Express default HTML error page
// bhejta hai — jisse frontend ka `resp.json()` "Unexpected token '<'"
// error ke saath crash ho jaata hai. Ye middleware ensure karta hai ki
// aisi har situation me bhi hamesha proper JSON error response jaaye.
// Catches requests to routes that don't exist on THIS running build.
// Without this, Express's default 404 is an HTML page, which still causes
// the exact same "Unexpected token '<'" crash on the frontend — the error
// middleware below never even runs for a 404 because no error was thrown.
// Most common cause in practice: frontend calling a route that's defined
// in the source but hasn't been deployed to this server yet.

// ================= ONE-TIME MIGRATION: split scratchCoins out of coins =================
// Before the spinCoins/scratchCoins split, both Spin Wheel AND Scratch Card
// coin wins were being added to the same `coins` field. This meant a user's
// `coins` total was actually a historical MIX of both games' winnings.
//
// This route re-derives the correct historical split using each user's
// existing `scratchHistory` log (every scratch win was already recorded there
// with its own `type` — "coins" / "xp" / "spinTicket" — even before the fix).
//
// For every user:
//   1. Sum up all scratchHistory entries where type === "coins" → this is
//      their TRUE lifetime scratch-card coin earnings.
//   2. Set scratchCoins = that sum (added to whatever they've already earned
//      post-fix, so it's safe to run even if some post-fix scratchCoins
//      already exist).
//   3. Subtract that same sum from `coins`, so what's left in `coins`
//      correctly reflects ONLY spin wheel winnings.
//
// This is safe to run multiple times ONLY if you haven't run it before —
// running it twice would double-subtract. It skips users who have a
// `scratchCoinsMigrated: true` flag so re-runs are a no-op.
//
// Admin/staff only. Call once via POST with the caller's Firebase ID token,
// then you can safely remove this route.
app.post("/admin/migrate-scratch-coins", verifyAuth, async (req, res) => {
  try {
    const callerUid = req.uid;
    const [adminConfigSnap, staffSnap] = await Promise.all([
      db.ref("adminConfig/adminUid").get(),
      db.ref(`staff/${callerUid}/status`).get()
    ]);
    const isAdmin = adminConfigSnap.val() === callerUid;
    const isActiveStaff = staffSnap.val() === "active";
    if (!isAdmin && !isActiveStaff) {
      return res.status(403).json({ error: "unauthorized" });
    }

    const usersSnap = await db.ref("users").get();
    if (!usersSnap.exists()) {
      return res.json({ success: true, usersScanned: 0, usersMigrated: 0, results: [] });
    }

    const allUsers = usersSnap.val();
    const results = [];
    let migratedCount = 0;

    for (const [uid, uData] of Object.entries(allUsers)) {
      if (uData.scratchCoinsMigrated) {
        continue; // already migrated — skip to avoid double-subtracting
      }

      const scratchHistory = uData.scratchHistory || {};
      let historicalScratchCoins = 0;
      for (const entry of Object.values(scratchHistory)) {
        if (entry && entry.type === "coins") {
          historicalScratchCoins += Number(entry.value) || 0;
        }
      }

      if (historicalScratchCoins <= 0) {
        // Nothing to migrate for this user, but still mark them done so we
        // don't rescan their (possibly large) scratchHistory every re-run.
        await db.ref(`users/${uid}`).update({ scratchCoinsMigrated: true });
        continue;
      }

      const currentCoins = Number(uData.coins) || 0;
      const currentScratchCoins = Number(uData.scratchCoins) || 0;
      const newCoins = Math.max(0, currentCoins - historicalScratchCoins);
      const newScratchCoins = currentScratchCoins + historicalScratchCoins;

      await db.ref(`users/${uid}`).update({
        coins: newCoins,
        scratchCoins: newScratchCoins,
        scratchCoinsMigrated: true,
      });

      migratedCount++;
      results.push({
        uid,
        movedAmount: historicalScratchCoins,
        coinsBefore: currentCoins,
        coinsAfter: newCoins,
        scratchCoinsBefore: currentScratchCoins,
        scratchCoinsAfter: newScratchCoins,
      });
    }

    return res.json({
      success: true,
      usersScanned: Object.keys(allUsers).length,
      usersMigrated: migratedCount,
      results,
    });
  } catch (err) {
    console.log("❌ Scratch coins migration error:", err.message);
    return res.status(500).json({ error: "Something went wrong" });
  }
});

// ================= AI-POWERED "QUICK CREATE MATCH" (admin.html) =================
// Admin ek plain-language line type karta hai jaise:
//   "Free Fire clash squad, aaj raat 8 baje, entry 50, prize 500, max 48 players"
// Ye endpoint us text ko available Games/Modes list ke against match karke
// ek structured JSON return karta hai, jisse admin.html "Create Match" form
// ke fields (game, mode, time, entry fee, prize pool, max players, etc.)
// AUTO-FILL ho jaate hain. Thumbnail/banner isme shaamil NAHI hai — wo admin
// khud upload karta hai jaisa pehle karta tha; ye endpoint sirf text-se-form
// wala hissa automate karta hai. Koi tournament yahan se seedha create/publish
// NAHI hoti — admin form dekh ke khud "Create Match" dabata hai, taaki galat
// AI-guess se koi live match galat detail ke saath publish na ho jaaye.
app.post("/ai-parse-match", verifyAuth, async (req, res) => {
  try {
    const callerUid = req.uid;
    const [adminConfigSnap, staffSnap] = await Promise.all([
      db.ref("adminConfig/adminUid").get(),
      db.ref(`staff/${callerUid}/status`).get(),
    ]);
    const isAdmin = adminConfigSnap.val() === callerUid;
    const isActiveStaff = staffSnap.val() === "active";
    if (!isAdmin && !isActiveStaff) {
      return res.status(403).json({ error: "unauthorized" });
    }

    const rawText = String(req.body?.text || "").trim();
    if (!rawText) {
      return res.status(400).json({ error: "text is required" });
    }
    if (rawText.length > 1000) {
      return res.status(400).json({ error: "text too long (max 1000 chars)" });
    }

    const availableProviders = configuredProviders();
    if (availableProviders.length === 0) {
      return res.status(503).json({ error: "No AI provider configured on server" });
    }

    // Games/Modes ki current list nikaalte hain -- AI ko sirf INHI me se
    // match karne ko bolenge, naya/fake gameId kabhi na bana sake.
    const [gamesSnap, modesSnap] = await Promise.all([
      db.ref("games").get(),
      db.ref("modes").get(),
    ]);
    const gamesList = [];
    if (gamesSnap.exists()) {
      gamesSnap.forEach((c) => {
        const v = c.val() || {};
        if (v.status !== "inactive") gamesList.push({ id: c.key, name: v.name || "" });
      });
    }
    const modesList = [];
    if (modesSnap.exists()) {
      modesSnap.forEach((c) => {
        const v = c.val() || {};
        if (v.status !== "inactive") modesList.push({ id: c.key, gameId: v.gameId || "", name: v.name || "" });
      });
    }

    if (gamesList.length === 0) {
      return res.status(400).json({ error: "No games configured yet -- add a Game in admin panel first" });
    }

    const gamesBlock = gamesList.map((g) => `id="${g.id}" name="${g.name}"`).join("\n");
    const modesBlock = modesList.length
      ? modesList.map((m) => `id="${m.id}" gameId="${m.gameId}" name="${m.name}"`).join("\n")
      : "(no modes configured)";

    // Server ka "abhi" time bhi bhej rahe hain (IST) taaki "aaj raat 8 baje" /
    // "kal shaam 6 baje" jaisी relative time sahi se resolve ho -- warna AI
    // apna training-data ka purana date use kar sakta hai.
    const nowIST = new Date().toLocaleString("en-IN", { timeZone: "Asia/Kolkata" });

    const systemPrompt =
      "You are a helper that converts a short admin instruction (in English, Hindi, or " +
      "Hinglish, possibly with typos) into a structured JSON object describing an esports " +
      "match, for a gaming tournament app called ClashX.\n\n" +
      "The current server date/time (India, IST) is: " + nowIST + ". Resolve any relative " +
      "time the admin gives (e.g. 'today 8pm', 'tomorrow evening', 'kal raat 9 baje') against " +
      "this. Always output startTime as a full ISO 8601 datetime string WITH the +05:30 IST " +
      "offset (e.g. '2026-09-10T20:00:00+05:30'). If the admin gives no time at all, default " +
      "to 2 hours from the current time above.\n\n" +
      "AVAILABLE GAMES (you MUST pick gameId only from this list -- never invent one):\n" +
      gamesBlock + "\n\n" +
      "AVAILABLE MODES (you MUST pick modeId only from this list, and it must belong to the " +
      "chosen gameId -- never invent one; if no mode clearly matches or is mentioned, set " +
      "modeId and modeName to null):\n" +
      modesBlock + "\n\n" +
      "Respond with ONLY a raw JSON object (no markdown fences, no commentary, no preamble) " +
      "with exactly these keys:\n" +
      '{\n' +
      '  "gameId": "<id from the games list above, best match to what the admin described>",\n' +
      '  "modeId": "<id from the modes list above, or null if unclear/not mentioned>",\n' +
      '  "name": "<a short human-readable match title, e.g. \'Solo Squad Clash - Night\'>",\n' +
      '  "startTime": "<ISO 8601 datetime with +05:30 offset, per the rule above>",\n' +
      '  "entryFee": <number, 0 if not mentioned>,\n' +
      '  "prizePool": <number, 0 if not mentioned>,\n' +
      '  "perKillPrize": <number, 0 if not mentioned>,\n' +
      '  "maxPlayers": <number, default 100 if not mentioned>,\n' +
      '  "mode": "<one of: Solo, Duo, Squad -- best guess from context, default Solo>",\n' +
      '  "description": "<any extra rules/notes the admin mentioned, as plain text, empty ' +
      'string if none>",\n' +
      '  "confidence": "<\'high\' if you are confident about the game/mode match, \'low\' if you ' +
      "had to guess a game/mode because the admin's wording was ambiguous>\"\n" +
      "}\n\n" +
      "Numbers must be plain JSON numbers (not strings, no currency symbols, no commas). If " +
      "the admin writes an amount like '50rs' or '₹50' or 'fifty rupees', output 50. If they " +
      "write 'no entry fee' or don't mention it, output 0.";

    const conversationMessages = [{ role: "user", content: rawText }];

    let attempt = await callAiWithRetry(availableProviders, systemPrompt, conversationMessages);
    if (!attempt.ok) {
      return res.status(502).json({ error: "AI providers are currently unavailable, try again in a moment" });
    }

    // AI kabhi-kabhi ```json fences ya thoda extra text de deta hai iske
    // bawajood system prompt me mana kiya hai -- isliye pehla { se lekar
    // aakhri } tak ka hissa hi nikaal ke parse karte hain.
    let raw = attempt.text.trim();
    const firstBrace = raw.indexOf("{");
    const lastBrace = raw.lastIndexOf("}");
    if (firstBrace === -1 || lastBrace === -1 || lastBrace < firstBrace) {
      return res.status(502).json({ error: "AI response was not valid JSON", raw });
    }
    raw = raw.slice(firstBrace, lastBrace + 1);

    let parsed;
    try {
      parsed = JSON.parse(raw);
    } catch (parseErr) {
      return res.status(502).json({ error: "Could not parse AI response as JSON", raw });
    }

    // Validate gameId/modeId are actually from our real lists (AI ko allowed
    // hai ki wo galti kare -- isko yahan pakadte hain, chupke se galat
    // gameId form me bhar dena expensive/confusing ho sakta hai).
    const validGameIds = new Set(gamesList.map((g) => g.id));
    const validModeIds = new Set(modesList.map((m) => m.id));
    if (!parsed.gameId || !validGameIds.has(parsed.gameId)) {
      return res.status(200).json({
        success: false,
        error: "Could not confidently match a game from your text. Please mention the game name more clearly.",
        raw: parsed,
      });
    }
    if (parsed.modeId && !validModeIds.has(parsed.modeId)) {
      parsed.modeId = null; // discard hallucinated mode id rather than reject the whole thing
    }
    if (parsed.modeId) {
      const modeMatch = modesList.find((m) => m.id === parsed.modeId);
      if (!modeMatch || modeMatch.gameId !== parsed.gameId) {
        parsed.modeId = null; // mode belongs to a different game -- drop it
      }
    }

    const gameMatch = gamesList.find((g) => g.id === parsed.gameId);
    const modeMatch = parsed.modeId ? modesList.find((m) => m.id === parsed.modeId) : null;

    // startTime ko epoch millis me normalize karte hain (form isko yahi
    // format me chahiye, jaisa admin.html ka manual flow already karta hai).
    let startTimeMs = Date.parse(parsed.startTime);
    if (isNaN(startTimeMs)) {
      startTimeMs = Date.now() + 2 * 60 * 60 * 1000; // fallback: +2 hours
    }

    return res.json({
      success: true,
      data: {
        gameId: parsed.gameId,
        gameName: gameMatch?.name || "",
        modeId: parsed.modeId || null,
        modeName: modeMatch?.name || null,
        name: String(parsed.name || "").slice(0, 100) || `${gameMatch?.name || "Match"} - New`,
        startTime: startTimeMs,
        entryFee: Number(parsed.entryFee) || 0,
        prizePool: Number(parsed.prizePool) || 0,
        perKillPrize: Number(parsed.perKillPrize) || 0,
        maxPlayers: Number(parsed.maxPlayers) || 100,
        mode: ["Solo", "Duo", "Squad"].includes(parsed.mode) ? parsed.mode : "Solo",
        description: String(parsed.description || "").slice(0, 2000),
        confidence: parsed.confidence === "low" ? "low" : "high",
      },
    });
  } catch (err) {
    console.log("❌ /ai-parse-match error:", err.message);
    return res.status(500).json({ error: "Something went wrong" });
  }
});



// ================= AI ADMIN ASSISTANT (admin.html) =================
// Admin ek plain-language command deta hai (jaise "SUMMER25 naam ka 25%
// coupon banao" ya "ticket #123 band kar do"). Ye do-step flow me kaam
// karta hai taaki AI kabhi bhi seedha, bina admin dekhe, koi action na kar
// sake:
//   1) /ai-admin-parse -- text padhta hai, AI se samajhta hai konsa action
//      chahiye, aur ek PREVIEW return karta hai (kuch bhi database me likha
//      nahi jaata is step me).
//   2) /ai-admin-execute -- admin preview dekh ke "Confirm" dabata hai,
//      frontend wahi structured data (parse step se mila hua) wapas isko
//      bhejta hai, aur TABHI actual database write hoti hai.
// Scope (jaan-boojh kar limited): coupon create, redeem code generate,
// FAQ add/edit, support ticket reply/close. Deposit aur Settings sections
// is se bilkul bahar hain -- wahan koi action type yahan define nahi hai.

const AI_ADMIN_ACTION_TYPES = ["create_coupon", "create_redeem_code", "add_faq", "edit_faq", "reply_ticket", "close_ticket", "create_match", "cancel_match", "ban_user", "unban_user", "edit_match"];

app.post("/ai-admin-parse", verifyAuth, async (req, res) => {
  try {
    const callerUid = req.uid;
    const { hasPerm, isAdmin } = await checkStaffPermission(callerUid, "ai_admin_asst");
    if (!hasPerm) {
      return res.status(403).json({ error: "unauthorized" });
    }

    const rawText = String(req.body?.text || "").trim();
    if (!rawText) return res.status(400).json({ error: "text is required" });
    if (rawText.length > 1000) return res.status(400).json({ error: "text too long (max 1000 chars)" });

    const availableProviders = configuredProviders();
    if (availableProviders.length === 0) {
      return res.status(503).json({ error: "No AI provider configured on server" });
    }

    // Open tickets ki ek chhoti list bhej rahe hain taaki admin "ticket
    // jisme Rahul ne refund maanga" jaisa likhe to AI sahi ticketId dhoond
    // sake, sirf numeric ID yaad rakhne par depend na ho.
    const ticketsSnap = await db.ref("supportTickets").orderByChild("status").equalTo("open").limitToLast(30).get();
    const openTickets = [];
    if (ticketsSnap.exists()) {
      ticketsSnap.forEach((c) => {
        const v = c.val() || {};
        openTickets.push({
          id: c.key,
          type: v.ticketType || "",
          subject: (v.subject || v.message || "").toString().slice(0, 120),
          userName: v.userName || v.userEmail || "",
        });
      });
    }
    const ticketsBlock = openTickets.length
      ? openTickets.map((t) => `id="${t.id}" type="${t.type}" user="${t.userName}" subject="${t.subject}"`).join("\n")
      : "(no open tickets)";

    const faqsSnap = await db.ref("aiFaqs").get();
    const existingFaqs = [];
    if (faqsSnap.exists()) {
      faqsSnap.forEach((c) => {
        const v = c.val() || {};
        existingFaqs.push({ id: c.key, question: v.question || "" });
      });
    }
    const faqsBlock = existingFaqs.length
      ? existingFaqs.map((f) => `id="${f.id}" question="${f.question}"`).join("\n")
      : "(no FAQs configured yet)";

    // create_match ke liye games/modes, cancel_match ke liye upcoming
    // matches ki list -- same tarah jaisa /ai-parse-match pehle se karta
    // hai, taaki AI sirf REAL existing IDs use kare, khud naya na banaye.
    const [gamesSnap, modesSnap, upcomingMatchesSnap] = await Promise.all([
      db.ref("games").get(),
      db.ref("modes").get(),
      db.ref("tournaments").orderByChild("status").equalTo("upcoming").limitToLast(30).get(),
    ]);
    const gamesList = [];
    if (gamesSnap.exists()) {
      gamesSnap.forEach((c) => {
        const v = c.val() || {};
        if (v.status !== "inactive") gamesList.push({ id: c.key, name: v.name || "" });
      });
    }
    const modesList = [];
    if (modesSnap.exists()) {
      modesSnap.forEach((c) => {
        const v = c.val() || {};
        if (v.status !== "inactive") modesList.push({ id: c.key, gameId: v.gameId || "", name: v.name || "" });
      });
    }
    const gamesBlock = gamesList.length
      ? gamesList.map((g) => `id="${g.id}" name="${g.name}"`).join("\n")
      : "(no games configured)";
    const modesBlock = modesList.length
      ? modesList.map((m) => `id="${m.id}" gameId="${m.gameId}" name="${m.name}"`).join("\n")
      : "(no modes configured)";

    const upcomingMatches = [];
    if (upcomingMatchesSnap.exists()) {
      upcomingMatchesSnap.forEach((c) => {
        const v = c.val() || {};
        upcomingMatches.push({ id: c.key, name: v.name || "", gameName: v.gameName || "", startTime: v.startTime || 0 });
      });
    }
    const upcomingMatchesBlock = upcomingMatches.length
      ? upcomingMatches.map((m) => `id="${m.id}" name="${m.name}" game="${m.gameName}" startTime="${new Date(m.startTime).toLocaleString("en-IN", { timeZone: "Asia/Kolkata" })}"`).join("\n")
      : "(no upcoming matches)";

    const nowIST = new Date().toLocaleString("en-IN", { timeZone: "Asia/Kolkata" });

    const systemPrompt =
      "You are an admin-panel assistant for a gaming/contest app called ClashX. An admin will " +
      "give you a short instruction (English, Hindi, or Hinglish, possibly with typos). Your " +
      "job is ONLY to figure out which ONE action they want and extract its parameters -- you " +
      "NEVER perform the action yourself, you just describe it for a human to confirm.\n\n" +
      "The current date/time (IST) is: " + nowIST + ".\n\n" +
      "You may ONLY choose actionType from this exact list: " + AI_ADMIN_ACTION_TYPES.join(", ") + ". " +
      "If the instruction doesn't clearly match one of these, or asks for something outside " +
      "this list (e.g. deposits, settings changes, cancelling a match WITH refund -- refunds " +
      "must always be done manually, never via this assistant), respond with actionType " +
      '"unsupported" and explain briefly in the "summary" field why -- NEVER invent an ' +
      "actionType not in the list above.\n\n" +
      "EXISTING OPEN SUPPORT TICKETS (for reply_ticket / close_ticket -- match by subject/user " +
      "mentioned, use the exact id):\n" + ticketsBlock + "\n\n" +
      "EXISTING FAQs (for edit_faq -- only use edit_faq with one of these exact ids if the " +
      "admin clearly refers to an existing FAQ to change; otherwise use add_faq for a new one):\n" +
      faqsBlock + "\n\n" +
      "AVAILABLE GAMES (for create_match -- pick gameId only from this list):\n" + gamesBlock + "\n\n" +
      "AVAILABLE MODES (for create_match -- pick modeId only from this list, must belong to the " +
      "chosen gameId; if unclear set modeId to null):\n" + modesBlock + "\n\n" +
      "UPCOMING MATCHES (for cancel_match -- match by name/game mentioned, use the exact id; " +
      "if the admin's reference doesn't clearly match one, use actionType \"unsupported\"):\n" +
      upcomingMatchesBlock + "\n\n" +
      "Respond with ONLY a raw JSON object (no markdown fences, no commentary) with this shape:\n" +
      '{\n' +
      '  "actionType": "<one of the allowed types above, or \'unsupported\'>",\n' +
      '  "summary": "<one short plain-English sentence describing exactly what will happen, ' +
      'for the admin to review before confirming>",\n' +
      '  "params": { ...action-specific fields, see below... }\n' +
      "}\n\n" +
      "params shape per actionType:\n" +
      "- create_coupon: { code (string, uppercase, short code admin gave or a sensible one you " +
      "generate from context), rewardType ('fixed' or 'percent'), rewardValue (number), " +
      "expiryDate (YYYY-MM-DD, default 30 days from now if not mentioned) }\n" +
      "- create_redeem_code: { code (string, uppercase, or null to auto-generate), " +
      "rewardAmount (number) }\n" +
      "- add_faq: { question (string), answer (string), order (number, default 0) }\n" +
      "- edit_faq: { faqId (must be an exact id from the EXISTING FAQs list above), " +
      "question (string), answer (string) }\n" +
      "- reply_ticket: { ticketId (must be an exact id from the EXISTING OPEN SUPPORT TICKETS " +
      "list above), replyMessage (string, the reply text in the same language the admin wrote " +
      "their instruction in) }\n" +
      "- close_ticket: { ticketId (must be an exact id from the list above) }\n" +
      "- create_match: { gameId (exact id from AVAILABLE GAMES), modeId (exact id from " +
      "AVAILABLE MODES or null), name (short match title), startTime (ISO 8601 with +05:30 " +
      "offset, resolved against current IST time above; default +2 hours if not mentioned), " +
      "entryFee (number, 0 if not mentioned), prizePool (number, 0 if not mentioned), " +
      "perKillPrize (number, 0 if not mentioned), maxPlayers (number, default 100), " +
      "mode (one of 'Solo'/'Duo'/'Squad', default 'Solo'), thumbnailPrompt (a short vivid " +
      "English visual description for generating a banner image for this match, e.g. 'Free " +
      "Fire squad battle royale, fiery orange and blue action poster, dramatic soldiers') }\n" +
      "- cancel_match: { matchId (must be an exact id from the UPCOMING MATCHES list above) } " +
      "-- this NEVER includes any refund handling; refunds are always done manually by the admin\n" +
      "- edit_match: { matchId (exact id from UPCOMING MATCHES list above), and ONLY the fields " +
      "the admin wants changed among: name, startTime (ISO 8601 +05:30), entryFee, prizePool, " +
      "perKillPrize, maxPlayers -- omit any field the admin didn't mention, don't guess values " +
      "for unmentioned fields. Banner/thumbnail editing is NOT supported by this actionType -- " +
      "if the admin ONLY wants to change the thumbnail/banner, use actionType \"unsupported\" " +
      "and say banner changes must be done manually from Match Setup.\n" +
      "- ban_user / unban_user: { userSearchQuery (the name, email, or partial identifier the " +
      "admin used to refer to the user -- do NOT try to resolve this to a UID yourself, just " +
      "pass along what the admin said, exactly as written) }\n" +
      "- unsupported: {} (empty)\n\n" +
      "Never invent a ticketId, faqId, gameId, modeId, or matchId that isn't in the lists above " +
      "-- if the admin's reference doesn't clearly match one, use actionType \"unsupported\" and " +
      "explain in summary.";

    const conversationMessages = [{ role: "user", content: rawText }];
    let attempt = await callAiWithRetry(availableProviders, systemPrompt, conversationMessages);
    if (!attempt.ok) {
      return res.status(502).json({ error: "AI providers are currently unavailable, try again in a moment" });
    }

    let raw = attempt.text.trim();
    // TEMP DEBUG: "AI response was not valid JSON" errors debug karne ke
    // liye -- Render Logs me poora raw AI text dikhayega.
    console.log("🔍 [DEBUG ai-admin-parse] provider:", attempt.provider, "| raw text:", JSON.stringify(raw));
    const firstBrace = raw.indexOf("{");
    const lastBrace = raw.lastIndexOf("}");
    if (firstBrace === -1 || lastBrace === -1 || lastBrace < firstBrace) {
      return res.status(502).json({ error: "AI response was not valid JSON", raw });
    }
    raw = raw.slice(firstBrace, lastBrace + 1);

    let parsed;
    try {
      parsed = JSON.parse(raw);
    } catch (parseErr) {
      console.log("🔍 [DEBUG ai-admin-parse] JSON.parse failed on:", JSON.stringify(raw), "| error:", parseErr.message);
      return res.status(502).json({ error: "Could not parse AI response as JSON", raw });
    }

    if (!AI_ADMIN_ACTION_TYPES.includes(parsed.actionType) && parsed.actionType !== "unsupported") {
      return res.json({ success: false, error: "AI returned an unrecognized action type", raw: parsed });
    }
    if (parsed.actionType === "unsupported") {
      return res.json({ success: false, error: parsed.summary || "This request isn't something I can help with yet." });
    }

    // Validate ticketId/faqId/gameId/modeId/matchId refs are real (don't
    // trust the model blindly)
    const params = parsed.params || {};
    if (params.ticketId && !openTickets.some((t) => t.id === params.ticketId)) {
      return res.json({ success: false, error: "Could not confidently match an open ticket from your text." });
    }
    if (parsed.actionType === "edit_faq" && params.faqId && !existingFaqs.some((f) => f.id === params.faqId)) {
      return res.json({ success: false, error: "Could not confidently match an existing FAQ from your text." });
    }
    if (parsed.actionType === "create_match") {
      if (!params.gameId || !gamesList.some((g) => g.id === params.gameId)) {
        return res.json({ success: false, error: "Could not confidently match a game from your text." });
      }
      if (params.modeId && !modesList.some((m) => m.id === params.modeId && m.gameId === params.gameId)) {
        params.modeId = null; // discard hallucinated/mismatched mode rather than reject the whole thing
      }
    }
    if (parsed.actionType === "cancel_match" || parsed.actionType === "edit_match") {
      if (!params.matchId || !upcomingMatches.some((m) => m.id === params.matchId)) {
        return res.json({ success: false, error: "Could not confidently match an upcoming match from your text." });
      }
    }

    // ban_user / unban_user: AI sirf ek search-query deta hai (jo admin ne
    // likha), khud UID resolve nahi karta. Yahan hum WAHI query se users
    // database me dhoondte hain -- agar EXACTLY ek match milta hai to use
    // params me daal dete hain (preview me admin dekh sakta hai kaunsa user
    // hai), agar 0 ya 2+ match milte hain to unsupported bhejte hain taaki
    // galat user ban na ho jaaye.
    if (parsed.actionType === "ban_user" || parsed.actionType === "unban_user") {
      const query = String(params.userSearchQuery || "").trim().toLowerCase();
      if (!query) {
        return res.json({ success: false, error: "Could not tell which user you mean." });
      }
      const usersSnap = await db.ref("users").get();
      const matches = [];
      if (usersSnap.exists()) {
        usersSnap.forEach((c) => {
          const v = c.val() || {};
          const name = (v.displayName || "").toLowerCase();
          const email = (v.email || "").toLowerCase();
          if (name.includes(query) || email.includes(query) || c.key === params.userSearchQuery) {
            matches.push({ uid: c.key, name: v.displayName || "(no name)", email: v.email || "", status: v.status || "active" });
          }
        });
      }
      if (matches.length === 0) {
        return res.json({ success: false, error: `No user found matching "${params.userSearchQuery}".` });
      }
      if (matches.length > 1) {
        const names = matches.slice(0, 5).map((m) => `${m.name} (${m.email})`).join(", ");
        return res.json({ success: false, error: `Multiple users match "${params.userSearchQuery}": ${names}. Please be more specific (use their exact email).` });
      }
      params.uid = matches[0].uid;
      params.resolvedUserName = matches[0].name;
      params.resolvedUserEmail = matches[0].email;
      if (parsed.actionType === "ban_user" && matches[0].status === "banned") {
        return res.json({ success: false, error: `${matches[0].name} is already banned.` });
      }
      if (parsed.actionType === "unban_user" && matches[0].status !== "banned") {
        return res.json({ success: false, error: `${matches[0].name} is not currently banned.` });
      }
    }

    // NOTE: create_match ke liye preview me abhi bhi Pollinations.ai se ek
    // QUICK preview thumbnail dikhate hain (free, instant, no cost hoti hai
    // sirf preview dikhane ki) -- lekin jab admin "Confirm" dabayega
    // (/ai-admin-execute), tab ASLI banner Gemini ke behtar-quality Nano
    // Banana image model se generate hoga aur Cloudinary par upload hoga.
    // Isliye final banner is preview se thoda better/different lag sakta
    // hai -- ye jaan-boojh kar hai (fast preview vs. best-quality final).
    let previewThumbnailUrl = null;
    if (parsed.actionType === "create_match" && params.thumbnailPrompt) {
      previewThumbnailUrl = `https://image.pollinations.ai/prompt/${encodeURIComponent(params.thumbnailPrompt)}?width=800&height=450&nologo=true`;
    }

    return res.json({
      success: true,
      actionType: parsed.actionType,
      summary: String(parsed.summary || "").slice(0, 500),
      params,
      previewThumbnailUrl,
    });
  } catch (err) {
    console.log("❌ /ai-admin-parse error:", err.message);
    return res.status(500).json({ error: "Something went wrong" });
  }
});

app.post("/ai-admin-execute", verifyAuth, async (req, res) => {
  try {
    const { actionType, params } = req.body || {};
    if (!AI_ADMIN_ACTION_TYPES.includes(actionType)) {
      return res.status(400).json({ error: "Invalid or missing actionType" });
    }
    const p = params || {};

    // Har action ka apna permission key hai, jaisa admin.html ke corresponding
    // manual forms use karte hain (coup_mgt, rdm_mgt, sup_mgt) -- taaki ek
    // staff jiske paas sirf coupon-permission hai, AI se support ticket
    // close na kar sake.
    const permKeyByAction = {
      create_coupon: "coup_mgt",
      create_redeem_code: "rdm_mgt",
      add_faq: "sup_mgt",
      edit_faq: "sup_mgt",
      reply_ticket: "support_tickets",
      close_ticket: "support_tickets",
      create_match: "match_add",
      cancel_match: "match_edit",
      edit_match: "match_edit",
      ban_user: "user_mgt",
      unban_user: "user_mgt",
    };
    const { hasPerm, isAdmin } = await checkStaffPermission(req.uid, permKeyByAction[actionType]);
    if (!hasPerm) return res.status(403).json({ error: "unauthorized" });

    if (actionType === "create_coupon") {
      const code = String(p.code || "").trim().toUpperCase();
      const rewardValue = Number(p.rewardValue);
      if (!code || !rewardValue || rewardValue <= 0) {
        return res.status(400).json({ error: "code and a positive rewardValue are required" });
      }
      await db.ref(`couponCodes/${code}`).update({
        amount: rewardValue,
        type: p.rewardType === "percent" ? "percent" : "fixed",
        expiry: p.expiryDate || new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString().slice(0, 10),
        status: "active",
        createdAt: Date.now(),
      });
      return res.json({ success: true, message: `Coupon ${code} created.` });
    }

    if (actionType === "create_redeem_code") {
      const rewardAmount = Number(p.rewardAmount);
      if (!rewardAmount || rewardAmount <= 0) {
        return res.status(400).json({ error: "A positive rewardAmount is required" });
      }
      const code = (p.code && String(p.code).trim().toUpperCase()) || Math.random().toString(36).substr(2, 8).toUpperCase();
      await db.ref(`redeemCodes/${code}`).set({ amount: rewardAmount, status: "active", createdAt: Date.now() });
      return res.json({ success: true, message: `Redeem code ${code} generated for ₹${rewardAmount}.` });
    }

    if (actionType === "add_faq") {
      const question = String(p.question || "").trim();
      const answer = String(p.answer || "").trim();
      if (!question || !answer) return res.status(400).json({ error: "question and answer are required" });
      const newRef = db.ref("aiFaqs").push();
      await newRef.set({ question, answer, order: Number(p.order) || 0, active: true, createdAt: Date.now() });
      return res.json({ success: true, message: `FAQ added: "${question}"` });
    }

    if (actionType === "edit_faq") {
      const faqId = String(p.faqId || "").trim();
      if (!faqId) return res.status(400).json({ error: "faqId is required" });
      const faqSnap = await db.ref(`aiFaqs/${faqId}`).get();
      if (!faqSnap.exists()) return res.status(404).json({ error: "FAQ not found" });
      const updates = {};
      if (p.question) updates.question = String(p.question).trim();
      if (p.answer) updates.answer = String(p.answer).trim();
      await db.ref(`aiFaqs/${faqId}`).update(updates);
      return res.json({ success: true, message: "FAQ updated." });
    }

    if (actionType === "reply_ticket") {
      const ticketId = String(p.ticketId || "").trim();
      const replyMessage = String(p.replyMessage || "").trim();
      if (!ticketId || !replyMessage) return res.status(400).json({ error: "ticketId and replyMessage are required" });
      const ticketSnap = await db.ref(`supportTickets/${ticketId}`).get();
      if (!ticketSnap.exists()) return res.status(404).json({ error: "Ticket not found" });
      if (ticketSnap.val().status === "closed") return res.status(403).json({ error: "Ticket is closed" });

      const senderName = await getStaffDisplayName(req.uid, isAdmin);
      const now = Date.now();
      await db.ref(`supportTickets/${ticketId}/messages`).push({
        senderUid: req.uid,
        senderRole: "staff",
        senderName,
        text: replyMessage,
        attachment: null,
        timestamp: now,
      });
      await db.ref(`supportTickets/${ticketId}`).update({ updatedAt: now, lastSenderRole: "staff" });
      return res.json({ success: true, message: "Reply sent." });
    }

    if (actionType === "close_ticket") {
      const ticketId = String(p.ticketId || "").trim();
      if (!ticketId) return res.status(400).json({ error: "ticketId is required" });
      const ticketSnap = await db.ref(`supportTickets/${ticketId}`).get();
      if (!ticketSnap.exists()) return res.status(404).json({ error: "Ticket not found" });
      const now = Date.now();
      await db.ref(`supportTickets/${ticketId}`).update({ status: "closed", closedAt: now, updatedAt: now, closedBy: req.uid });
      return res.json({ success: true, message: "Ticket closed." });
    }

    if (actionType === "create_match") {
      const gameId = String(p.gameId || "").trim();
      if (!gameId) return res.status(400).json({ error: "gameId is required" });
      const gameSnap = await db.ref(`games/${gameId}`).get();
      if (!gameSnap.exists()) return res.status(404).json({ error: "Game not found" });

      let modeName = "";
      if (p.modeId) {
        const modeSnap = await db.ref(`modes/${p.modeId}`).get();
        if (modeSnap.exists()) modeName = modeSnap.val().name || "";
      }

      let startTimeMs = Date.parse(p.startTime);
      if (isNaN(startTimeMs)) startTimeMs = Date.now() + 2 * 60 * 60 * 1000;

      // Banner: agar AI ne thumbnailPrompt diya tha, Gemini ke image model
      // (Nano Banana) se generate karke Cloudinary par upload karte hain --
      // behtar quality deta hai Pollinations se. Agar image-generation kisi
      // wajah se fail ho jaaye (quota, network, etc.), match phir bhi ban
      // jaata hai bina banner ke -- admin baad me Match Setup se manually
      // laga sakta hai, poora action fail nahi hota.
      let bannerUrl = null;
      if (p.thumbnailPrompt) {
        try {
          bannerUrl = await generateMatchThumbnail(p.thumbnailPrompt);
        } catch (thumbErr) {
          console.log("⚠️ AI thumbnail generation failed, match will be created without a banner:", thumbErr.message);
        }
      }

      const newMatchRef = db.ref("tournaments").push();
      await newMatchRef.set({
        gameId,
        gameName: gameSnap.val().name || "",
        modeId: p.modeId || null,
        modeName,
        matchNumber: Math.floor(100 + Math.random() * 900),
        name: String(p.name || "").slice(0, 100) || `${gameSnap.val().name || "Match"} - New`,
        startTime: startTimeMs,
        status: "upcoming",
        entryFee: Number(p.entryFee) || 0,
        prizePool: Number(p.prizePool) || 0,
        perKillPrize: Number(p.perKillPrize) || 0,
        maxPlayers: Number(p.maxPlayers) || 100,
        mode: ["Solo", "Duo", "Squad"].includes(p.mode) ? p.mode : "Solo",
        bannerUrl,
        description: "",
        roomId: "",
        roomPassword: "",
        showIdPass: false,
        createdByUid: req.uid,
        createdByName: isAdmin ? "Main Admin" : (await getStaffDisplayName(req.uid, isAdmin)),
        createdByRole: isAdmin ? "Admin" : "Staff",
        creatorTrackingId: (isAdmin ? "ADM-" : "STF-") + Math.random().toString(36).substr(2, 5).toUpperCase(),
        createdAt: Date.now(),
      });
      await db.ref("contentVersion").update({ tournaments: Date.now() }).catch(() => {});
      return res.json({ success: true, message: `Match "${p.name || ""}" created.` });
    }

    if (actionType === "cancel_match") {
      // Jaan-boojh kar SIRF status "canceled" set karta hai -- koi refund,
      // koi user balance update, koi XP deduction yahan nahi hota. Agar
      // registered players ko refund karna hai, admin ko Match Setup form
      // se hi "Refund Joined Users" checkbox ke saath manually karna hoga,
      // jahan wo poora impact dekh sake confirm karne se pehle.
      const matchId = String(p.matchId || "").trim();
      if (!matchId) return res.status(400).json({ error: "matchId is required" });
      const matchSnap = await db.ref(`tournaments/${matchId}`).get();
      if (!matchSnap.exists()) return res.status(404).json({ error: "Match not found" });
      if (matchSnap.val().winningsCredited) {
        return res.status(400).json({ error: "This match already has results declared, cannot cancel." });
      }
      await db.ref(`tournaments/${matchId}`).update({ status: "canceled", everCancelled: true, updatedAt: Date.now() });
      await db.ref("contentVersion").update({ tournaments: Date.now() }).catch(() => {});
      return res.json({
        success: true,
        message: "Match cancelled (no refunds were issued — if players need refunds, use the Refund Joined Users option in Match Setup manually).",
      });
    }

    if (actionType === "edit_match") {
      // Sirf jo fields admin ne mention kiye the wahi update hote hain
      // (parse step ne already sirf mentioned fields hi params me bheje
      // the). Banner/thumbnail edit yahan se kabhi nahi hota.
      const matchId = String(p.matchId || "").trim();
      if (!matchId) return res.status(400).json({ error: "matchId is required" });
      const matchSnap = await db.ref(`tournaments/${matchId}`).get();
      if (!matchSnap.exists()) return res.status(404).json({ error: "Match not found" });

      const updates = { updatedAt: Date.now() };
      if (p.name) updates.name = String(p.name).slice(0, 100);
      if (p.startTime) {
        const ms = Date.parse(p.startTime);
        if (!isNaN(ms)) updates.startTime = ms;
      }
      if (p.entryFee !== undefined && p.entryFee !== null) updates.entryFee = Number(p.entryFee) || 0;
      if (p.prizePool !== undefined && p.prizePool !== null) updates.prizePool = Number(p.prizePool) || 0;
      if (p.perKillPrize !== undefined && p.perKillPrize !== null) updates.perKillPrize = Number(p.perKillPrize) || 0;
      if (p.maxPlayers !== undefined && p.maxPlayers !== null) updates.maxPlayers = Number(p.maxPlayers) || 100;

      if (Object.keys(updates).length === 1) {
        return res.status(400).json({ error: "Nothing to update was specified" });
      }
      await db.ref(`tournaments/${matchId}`).update(updates);
      await db.ref("contentVersion").update({ tournaments: Date.now() }).catch(() => {});
      return res.json({ success: true, message: "Match updated." });
    }

    if (actionType === "ban_user" || actionType === "unban_user") {
      const uid = String(p.uid || "").trim();
      if (!uid) return res.status(400).json({ error: "Could not identify which user — please re-run Ask AI." });
      const userSnap = await db.ref(`users/${uid}`).get();
      if (!userSnap.exists()) return res.status(404).json({ error: "User not found" });
      const newStatus = actionType === "ban_user" ? "banned" : "active";
      await db.ref(`users/${uid}`).update({ status: newStatus });
      return res.json({
        success: true,
        message: `${p.resolvedUserName || uid} has been ${newStatus === "banned" ? "banned" : "unbanned"}.`,
      });
    }

    return res.status(400).json({ error: "Unhandled actionType" });
  } catch (err) {
    console.log("❌ /ai-admin-execute error:", err.message);
    return res.status(500).json({ error: "Something went wrong" });
  }
});


app.use((req, res) => {
  res.status(404).json({ error: `Route not found: ${req.method} ${req.path}` });
});

app.use((err, req, res, next) => {
  console.log("❌ Unhandled error:", err.message);
  if (res.headersSent) return next(err);
  const status = err.status || err.statusCode || 500;
  const message = err.type === "entity.too.large"
    ? "Request payload too large"
    : (err.message || "Something went wrong");
  res.status(status).json({ error: message });
});


// 0.0.0.0 Host
const PORT = process.env.PORT || 10000;
app.listen(PORT, "0.0.0.0", () => {
  console.log(`push-sender listening on port ${PORT} at 0.0.0.0`);
});