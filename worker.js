// ReversalX VPN Decode Bot — Cloudflare Worker
//
// Public routes:
//   POST /telegram/webhook
//   GET  /health
//
// Required Cloudflare Worker secrets:
//   TG_BOT_TOKEN
//   TG_WEBHOOK_SECRET
//   GH_TOKEN

const REPOSITORY = "Matrixzat/vpn-decryptor";
const STATUS_MESSAGE_TTL_SECONDS = 20 * 60;
const STATUS_CLEANUP_PREFIX = "upload-status:";
const LOGO_URL =
  "https://raw.githubusercontent.com/Matrixzat/vpn-decryptor/main/assets/reversalx-vpn-decode-logo.png";
const MAX_FILE_BYTES = 8 * 1024 * 1024;
const GROUP_URL = "https://t.me/reversalxmods1";
const JOIN_BUTTONS = [
  { text: "📢 Channel 1 📢", url: "https://t.me/reversemoda" },
  { text: "📢 Channel 2 📢", url: "https://t.me/reversalxmods" },
  { text: "👥 Join Group 👥", url: GROUP_URL },
];
const REQUIRED_MEMBERSHIP_CHAT_IDS = [
  "@reversemoda",
  "@reversalxmods",
  "@reversalxmods1",
];
const ADMIN_USER_IDS = new Set(["853645999", "277397055", "1430400464"]);

const SUPPORTED_FORMATS = new Map([
  [".ehi", "HTTP Injector"],
  [".npvt", "NPV Tunnel"],
  [".hc", "HTTP Custom"],
  [".dark", "Dark Tunnel"],
  [".nm", "NetMod"],
  [".tnl", "OpenTunnel"],
  [".ziv", "ZIVPN"],
  [".hat", "HAT Tunnel"],
  [".sip", "SocksIP / SocksTunnel"],
  [".ssc", "SSC Custom / raw hex"],
]);

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    if (request.method === "GET" && url.pathname === "/health") {
      return json({
        ok: true,
        service: "telegram-github-decoder",
        telegramConfigured: Boolean(env.TG_BOT_TOKEN),
        githubConfigured: Boolean(env.GH_TOKEN),
        cleanupConfigured: Boolean(env.MESSAGE_CLEANUP),
      });
    }

    if (request.method !== "POST" || url.pathname !== "/telegram/webhook") {
      return json({ error: "not found" }, 404);
    }

    if (!env.TG_BOT_TOKEN || !env.TG_WEBHOOK_SECRET || !env.GH_TOKEN) {
      return json({ error: "worker is not configured" }, 503);
    }

    const suppliedSecret = request.headers.get(
      "X-Telegram-Bot-Api-Secret-Token",
    );
    if (suppliedSecret !== env.TG_WEBHOOK_SECRET) {
      return new Response("unauthorized", { status: 401 });
    }

    let update;
    try {
      update = await request.json();
    } catch {
      return json({ error: "invalid JSON" }, 400);
    }

    // Telegram expects a quick 2xx response. The Worker can continue the
    // Telegram/GitHub work after the webhook request has been accepted.
    const work = handleUpdate(update, env).catch((error) => {
      console.error(
        "update handling failed",
        error instanceof Error ? error.message : "unknown error",
      );
    });
    ctx.waitUntil(work);
    return json({ ok: true });
  },

  async scheduled(_controller, env, ctx) {
    ctx.waitUntil(
      processStatusMessageCleanup(env).catch((error) => {
        console.error(
          "status cleanup failed",
          error instanceof Error ? error.message : "unknown error",
        );
      }),
    );
  },
};

async function handleUpdate(update, env) {
  if (update?.callback_query) {
    await handleCallbackQuery(update.callback_query, env);
    return;
  }

  const message = update?.message || update?.channel_post;
  if (!message?.chat?.id) return;

  const chatId = String(message.chat.id);
  const command = extractCommand(message.text);
  if (isChannelChat(message.chat)) {
    if (message.document || command === "/start" || command === "/help") {
      await sendCommunityRestriction(env, chatId);
    }
    return;
  }

  if (isPrivateChat(message.chat) && !isAdminUser(message.from?.id)) {
    const access = await checkPrivateAccess(env, message.from?.id);
    if (!access.allowed) {
      await sendAccessGate(env, chatId, message.from, access.lookupFailed);
      return;
    }
  }

  if (command === "/start" || command === "/help") {
    await sendWelcome(env, chatId, message.from, command);
    return;
  }

  if (message.document) {
    await handleDocument(env, chatId, message);
    return;
  }

  if (message.text) {
    await sendMessage(
      env,
      chatId,
      "Send a supported configuration file, or use /help to see the available formats.",
    );
  }
}

async function sendWelcome(env, chatId, user, command) {
  await telegramRequest(env, "sendPhoto", {
    chat_id: chatId,
    photo: LOGO_URL,
    parse_mode: "HTML",
    caption: welcomeCaption(user, command),
    reply_markup: welcomeKeyboard(),
  });
}

async function handleCallbackQuery(callback, env) {
  const callbackAnswer = {
    callback_query_id: callback.id,
  };
  if (callback.data === "verify_access") {
    callbackAnswer.text = "Checking your channel access...";
  }
  await telegramRequest(env, "answerCallbackQuery", callbackAnswer);

  const message = callback.message;
  if (!message?.chat?.id || !message.message_id) return;

  let replyMarkup;
  if (callback.data === "join_channels") {
    replyMarkup = isChannelChat(message.chat)
      ? membershipKeyboard(false)
      : channelKeyboard(!isGroupChat(message.chat));
  } else if (callback.data === "verify_access") {
    if (isGroupChat(message.chat)) {
      await sendMessage(
        env,
        String(message.chat.id),
        "✅ <b>Group access is unrestricted.</b>\n\nSend a supported configuration file to begin.",
        "HTML",
      );
      return;
    }
    if (isChannelChat(message.chat)) {
      await sendCommunityRestriction(env, String(message.chat.id));
      return;
    }

    const access = isAdminUser(callback.from?.id)
      ? { allowed: true, lookupFailed: false }
      : await checkPrivateAccess(env, callback.from?.id);
    if (access.allowed) {
      await sendMessage(
        env,
        String(message.chat.id),
        `✅ <b>ACCESS VERIFIED</b>
╰━━━━━━━━━━━━━━━━━━╯

🔓 Private decoding is now enabled for your account.
📤 <b>Send your configuration file again to begin.</b>`,
        "HTML",
      );
    } else {
      await sendAccessGate(
        env,
        String(message.chat.id),
        callback.from,
        access.lookupFailed,
      );
    }
    return;
  } else if (callback.data === "welcome") {
    if (isChannelChat(message.chat)) {
      await sendCommunityRestriction(env, String(message.chat.id));
      return;
    }
    replyMarkup = welcomeKeyboard();
  } else {
    return;
  }

  await telegramRequest(env, "editMessageReplyMarkup", {
    chat_id: message.chat.id,
    message_id: message.message_id,
    reply_markup: replyMarkup,
  });
}

async function handleDocument(env, chatId, message) {
  const document = message.document;
  const filename = safeFilename(document.file_name);
  if (!filename) {
    await sendMessage(env, chatId, "That filename is not valid.");
    return;
  }

  const extension = extensionOf(filename);
  const decoderName = SUPPORTED_FORMATS.get(extension);
  if (!decoderName) {
    await sendMessage(
      env,
      chatId,
      "This format is not supported yet. Use /help to see the supported extensions.",
    );
    return;
  }

  if (document.file_size && document.file_size > MAX_FILE_BYTES) {
    await sendMessage(
      env,
      chatId,
      "That file is too large. The current limit is 8 MiB.",
    );
    return;
  }

  const statusMessage = await sendMessage(
    env,
    chatId,
    `📥 <b>UPLOAD RECEIVED</b>
╰━━━━━━━━━━━━━━━━━━╯

📄 <b>FILE</b>
└ <code>${escapeHtml(filename)}</code>

🧩 <b>FORMAT</b>
└ <b>${escapeHtml(decoderName)}</b>

👤 <b>REQUESTER</b>
└ ${mentionName(message.from)}

⚡ <b>STATUS</b>
└ <i>Analyzing configuration...</i>
🛡️ <b>Protection:</b> Active`,
    "HTML",
  );

  const cleanupPromise = scheduleStatusMessageDeletion(
    env,
    chatId,
    statusMessage?.message_id,
  ).catch((error) => {
    console.error(
      "status cleanup scheduling failed",
      error instanceof Error ? error.message : "unknown error",
    );
  });

  try {
    const jobId = `${chatId}-${updateId(message)}-${crypto.randomUUID()}`;
    await Promise.all([
      cleanupPromise,
      dispatchDecode(env, {
        job_id: jobId,
        chat_id: chatId,
        filename,
        telegram_file_id: document.file_id,
        first_name: message.from?.first_name || "",
        last_name: message.from?.last_name || "",
        username: message.from?.username || "",
        user_id: String(message.from?.id || ""),
        chat_type: message.chat?.type || "",
      }),
    ]);
  } catch (error) {
    console.error("decode dispatch failed", error instanceof Error ? error.message : "unknown error");
    await sendMessage(
      env,
      chatId,
      "⚠️ I could not submit that file for decoding. Please try again later.",
    );
  }
}

async function dispatchDecode(env, payload) {
  const response = await fetch(
    `https://api.github.com/repos/${REPOSITORY}/dispatches`,
    {
      method: "POST",
      headers: githubHeaders(env),
      body: JSON.stringify({
        event_type: "decode-config",
        client_payload: payload,
      }),
    },
  );
  if (!response.ok) {
    throw new Error(`GitHub dispatch failed with HTTP ${response.status}`);
  }
}

async function telegramRequest(env, method, payload) {
  const response = await fetch(
    `https://api.telegram.org/bot${env.TG_BOT_TOKEN}/${method}`,
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    },
  );
  const data = await response.json().catch(() => null);
  if (!response.ok || !data?.ok) {
    throw new Error(`Telegram ${method} failed with HTTP ${response.status}`);
  }
  return data.result;
}

async function sendMessage(env, chatId, text, parseMode) {
  const payload = { chat_id: chatId, text };
  if (parseMode) payload.parse_mode = parseMode;
  return telegramRequest(env, "sendMessage", payload);
}

async function scheduleStatusMessageDeletion(env, chatId, messageId) {
  if (!env.MESSAGE_CLEANUP) {
    throw new Error("MESSAGE_CLEANUP binding is not configured");
  }
  if (!Number.isInteger(messageId)) {
    throw new Error("Telegram did not return a status message ID");
  }

  const deleteAt =
    Math.floor(Date.now() / 1000) + STATUS_MESSAGE_TTL_SECONDS;
  const key = `${STATUS_CLEANUP_PREFIX}${deleteAt}:${crypto.randomUUID()}`;
  await env.MESSAGE_CLEANUP.put(
    key,
    JSON.stringify({
      chat_id: String(chatId),
      message_id: messageId,
      delete_at: deleteAt,
    }),
    { expirationTtl: STATUS_MESSAGE_TTL_SECONDS + 60 * 60 },
  );
}

async function processStatusMessageCleanup(env) {
  if (!env.MESSAGE_CLEANUP) {
    console.error("MESSAGE_CLEANUP binding is not configured");
    return;
  }

  const now = Math.floor(Date.now() / 1000);
  let cursor;
  do {
    const page = await env.MESSAGE_CLEANUP.list({
      prefix: STATUS_CLEANUP_PREFIX,
      limit: 100,
      ...(cursor ? { cursor } : {}),
    });

    await Promise.all(
      page.keys.map(async ({ name }) => {
        const raw = await env.MESSAGE_CLEANUP.get(name);
        if (!raw) return;

        let record;
        try {
          record = JSON.parse(raw);
        } catch {
          await env.MESSAGE_CLEANUP.delete(name);
          return;
        }

        if (
          !record ||
          !Number.isFinite(record.delete_at) ||
          record.delete_at > now ||
          !record.chat_id ||
          !Number.isInteger(record.message_id)
        ) {
          return;
        }

        try {
          await telegramRequest(env, "deleteMessage", {
            chat_id: record.chat_id,
            message_id: record.message_id,
          });
          await env.MESSAGE_CLEANUP.delete(name);
        } catch (error) {
          console.error(
            "status message delete failed",
            error instanceof Error ? error.message : "unknown error",
          );
        }
      }),
    );

    cursor = page.list_complete ? undefined : page.cursor;
  } while (cursor);
}

async function sendAccessGate(
  env,
  chatId,
  user,
  lookupFailed = false,
) {
  const heading = "🔐 <b>PRIVATE ACCESS REQUIRED</b>";
  const explanation = lookupFailed
    ? "I could not confirm your channel access right now. Please tap a button above to join."
    : "To use the decoder in a private chat, join all three ReversalX community destinations below.";

  await telegramRequest(env, "sendMessage", {
    chat_id: chatId,
    text: `${heading}
╰━━━━━━━━━━━━━━━━━━╯

${explanation}

1️⃣ <b>Official Channel 1</b>
2️⃣ <b>Official Channel 2</b>
3️⃣ <b>ReversalX Community Group</b>

📌 After joining, tap <b>✅ Verify Access</b>.
Once confirmed, I will unlock private decoding and ask you to send your file again.

👤 Requester: ${mentionName(user)}`,
    parse_mode: "HTML",
    reply_markup: membershipKeyboard(),
  });
}

async function sendCommunityRestriction(env, chatId) {
  await telegramRequest(env, "sendMessage", {
    chat_id: chatId,
    text: `🚫 <b>PRIVATE CHAT ONLY</b>
╰━━━━━━━━━━━━━━━━━━╯

This bot does not decode files inside groups or channels.

🔐 To use the decoder:
1️⃣ Join Official Channel 1
2️⃣ Join Official Channel 2
3️⃣ Join the ReversalX Community Group

📩 After joining, open a private chat with the bot and tap <b>✅ Verify Access</b>.
Your file can only be processed in private chat.`,
    parse_mode: "HTML",
    reply_markup: membershipKeyboard(false),
  });
}

function githubHeaders(env) {
  return {
    Authorization: `Bearer ${env.GH_TOKEN}`,
    Accept: "application/vnd.github+json",
    "Content-Type": "application/json",
    "User-Agent": "ReversalX-VPN-Decode-Worker/1.0",
    "X-GitHub-Api-Version": "2022-11-28",
  };
}

function welcomeCaption(user = {}, command = "/start") {
  const badgeName = badgeNameFor(user);
  const userId = escapeHtml(String(user.id || "Not provided").slice(0, 64));
  const formats = [...SUPPORTED_FORMATS.entries()]
    .map(([extension, description]) => `• <code>${extension}</code> — ${description}`)
    .join("\n");

  const caption = `🔐 <b>ReversalX VPN Decode Bot</b> 🔐

👋 Welcome, <b>${badgeName}</b>!

🧩 Send a supported VPN configuration file and receive a decrypted readable result.

👤 <b>Your Session</b>
🔹 User: <b>${badgeName}</b>
🔹 ID: <code>${userId}</code>
🔹 Status: ✅ Active

✨ <b>Supported Formats</b>
${formats}

🚀 <b>How to Use</b>
Send a supported vpn file → wait → receive the result.

📌 <b>Commands</b>
/start — show this welcome
/help — show formats and usage

⚠️ <i>Only decode files you own or are authorized to inspect.</i>`;

  if (caption.length > 1024) {
    throw new Error(`Telegram caption is too long (${caption.length} characters)`);
  }
  return caption;
}

function welcomeKeyboard() {
  return {
    inline_keyboard: [
      [{ text: "📢 Join Our Channels 📢", callback_data: "join_channels" }],
      [{ text: "👥 Join Our Group 👥", url: GROUP_URL }],
    ],
  };
}

function channelKeyboard(includeVerify = true) {
  const rows = JOIN_BUTTONS.map((button) => [{ ...button }]);
  if (includeVerify) {
    rows.push([{ text: "✅ Verify Access", callback_data: "verify_access" }]);
  }
  rows.push([{ text: "🔙 Back 🔙", callback_data: "welcome" }]);
  return { inline_keyboard: rows };
}

function membershipKeyboard(includeVerify = true) {
  const rows = JOIN_BUTTONS.map((button) => [{ ...button }]);
  if (includeVerify) {
    rows.push([{ text: "✅ Verify Access", callback_data: "verify_access" }]);
  }
  return {
    inline_keyboard: rows,
  };
}

function isPrivateChat(chat) {
  return chat?.type === "private";
}

function isGroupChat(chat) {
  return chat?.type === "group" || chat?.type === "supergroup";
}

function isChannelChat(chat) {
  return chat?.type === "channel";
}

function isAdminUser(userId) {
  return userId !== undefined && ADMIN_USER_IDS.has(String(userId));
}

async function checkPrivateAccess(env, userId) {
  if (!userId) return { allowed: false, lookupFailed: true };

  const checks = await Promise.all(
    REQUIRED_MEMBERSHIP_CHAT_IDS.map(async (requiredChatId) => {
      try {
        const member = await telegramRequest(env, "getChatMember", {
          chat_id: requiredChatId,
          user_id: userId,
        });
        return { allowed: hasChannelAccess(member), lookupFailed: false };
      } catch (error) {
        console.error(
          "channel membership check failed",
          error instanceof Error ? error.message : "unknown error",
        );
        return { allowed: false, lookupFailed: true };
      }
    }),
  );

  return {
    allowed: checks.every((check) => check.allowed),
    lookupFailed: checks.some((check) => check.lookupFailed),
  };
}

function hasChannelAccess(member) {
  if (!member || typeof member.status !== "string") return false;
  if (["creator", "administrator", "member"].includes(member.status)) return true;
  return member.status === "restricted" && member.is_member === true;
}

function displayName(user) {
  const fullName = [user.first_name, user.last_name]
    .filter(Boolean)
    .join(" ")
    .trim()
    .slice(0, 48);
  if (fullName) return escapeHtml(fullName);
  const username = String(user.username || "").replace(/^@/, "").slice(0, 48);
  return username ? `@${escapeHtml(username)}` : "there";
}

function badgeNameFor(user) {
  const name = displayName(user)
    .replace(/^(?:🏅\s*)+|(?:\s*🏅)+$/g, "")
    .trim();
  return `🏅${name || "there"}🏅`;
}

function mentionName(user) {
  const badgeName = badgeNameFor(user);
  if (user?.id) {
    return `<a href="tg://user?id=${escapeHtml(String(user.id))}">${badgeName}</a>`;
  }
  return `<b>${badgeName}</b>`;
}

function extractCommand(text) {
  if (typeof text !== "string") return "";
  const firstWord = text.trim().split(/\s+/, 1)[0].toLowerCase();
  return firstWord.split("@", 1)[0];
}

function safeFilename(value) {
  if (typeof value !== "string") return "";
  const filename = value.trim();
  if (
    !filename ||
    filename === "." ||
    filename === ".." ||
    filename.includes("/") ||
    filename.includes("\\") ||
    filename.includes("\n") ||
    filename.includes("\r")
  ) {
    return "";
  }
  return filename.slice(0, 180);
}

function extensionOf(filename) {
  const dot = filename.lastIndexOf(".");
  return dot >= 0 ? filename.slice(dot).toLowerCase() : "";
}

function updateId(message) {
  return String(message.message_id || crypto.randomUUID());
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}