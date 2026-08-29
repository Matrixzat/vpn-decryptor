var __defProp = Object.defineProperty;
var __name = (target, value) => __defProp(target, "name", { value, configurable: true });

// vpn-decryptor/worker.js
var __defProp2 = Object.defineProperty;
var __name2 = /* @__PURE__ */ __name((target, value) => __defProp2(target, "name", { value, configurable: true }), "__name");
var REPOSITORY = "Matrixzat/vpn-decryptor";
var STATUS_MESSAGE_TTL_SECONDS = 20 * 60;
var STATUS_CLEANUP_PREFIX = "upload-status:";
var LOGO_URL = "https://raw.githubusercontent.com/Matrixzat/vpn-decryptor/main/assets/reversalx-vpn-decode-logo.png";
var MAX_FILE_BYTES = 8 * 1024 * 1024;
var GROUP_URL = "https://t.me/reversalxmods1";
var JOIN_BUTTONS = [
  { text: "\u{1F4E2} Channel 1 \u{1F4E2}", url: "https://t.me/reversemoda" },
  { text: "\u{1F4E2} Channel 2 \u{1F4E2}", url: "https://t.me/reversalxmods" },
  { text: "\u{1F465} Join Group \u{1F465}", url: GROUP_URL }
];
var REQUIRED_MEMBERSHIP_CHAT_IDS = [
  "@reversemoda",
  "@reversalxmods",
  "@reversalxmods1"
];
var ADMIN_USER_IDS = /* @__PURE__ */ new Set(["853645999", "277397055", "1430400464"]);
var SUPPORTED_FORMATS = /* @__PURE__ */ new Map([
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
  [".sks", "SocksHTTP"],
  [".v2box", "V2Box / V2Ray export (unprotected)"]
]);
var worker_default = {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    if (request.method === "GET" && url.pathname === "/health") {
      return json({
        ok: true,
        service: "telegram-github-decoder",
        telegramConfigured: Boolean(env.TG_BOT_TOKEN),
        githubConfigured: Boolean(env.GH_TOKEN),
        cleanupConfigured: Boolean(env.MESSAGE_CLEANUP)
      });
    }
    if (request.method !== "POST" || url.pathname !== "/telegram/webhook") {
      return json({ error: "not found" }, 404);
    }
    if (!env.TG_BOT_TOKEN || !env.TG_WEBHOOK_SECRET || !env.GH_TOKEN) {
      return json({ error: "worker is not configured" }, 503);
    }
    const suppliedSecret = request.headers.get(
      "X-Telegram-Bot-Api-Secret-Token"
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
    const work = handleUpdate(update, env).catch((error) => {
      console.error(
        "update handling failed",
        error instanceof Error ? error.message : "unknown error"
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
          error instanceof Error ? error.message : "unknown error"
        );
      })
    );
  }
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
  // Do not interrupt normal group conversation. Groups should only receive
  // responses for commands and uploaded documents handled above.
  if (message.text && isPrivateChat(message.chat)) {
    await sendMessage(
      env,
      chatId,
      "Send a supported configuration file, or use /help to see the available formats."
    );
  }
}
__name(handleUpdate, "handleUpdate");
__name2(handleUpdate, "handleUpdate");
async function sendWelcome(env, chatId, user, command) {
  await telegramRequest(env, "sendPhoto", {
    chat_id: chatId,
    photo: LOGO_URL,
    parse_mode: "HTML",
    caption: welcomeCaption(user, command),
    reply_markup: welcomeKeyboard()
  });
}
__name(sendWelcome, "sendWelcome");
__name2(sendWelcome, "sendWelcome");
async function handleCallbackQuery(callback, env) {
  const callbackAnswer = {
    callback_query_id: callback.id
  };
  if (callback.data === "verify_access") {
    callbackAnswer.text = "Checking your channel access...";
  }
  await telegramRequest(env, "answerCallbackQuery", callbackAnswer);
  const message = callback.message;
  if (!message?.chat?.id || !message.message_id) return;
  let replyMarkup;
  if (callback.data === "join_channels") {
    replyMarkup = isChannelChat(message.chat) ? membershipKeyboard(false) : channelKeyboard(!isGroupChat(message.chat));
  } else if (callback.data === "verify_access") {
    if (isGroupChat(message.chat)) {
      await sendMessage(
        env,
        String(message.chat.id),
        "\u2705 <b>Group access is unrestricted.</b>\n\nSend a supported configuration file to begin.",
        "HTML"
      );
      return;
    }
    if (isChannelChat(message.chat)) {
      await sendCommunityRestriction(env, String(message.chat.id));
      return;
    }
    const access = isAdminUser(callback.from?.id) ? { allowed: true, lookupFailed: false } : await checkPrivateAccess(env, callback.from?.id);
    if (access.allowed) {
      await sendMessage(
        env,
        String(message.chat.id),
        `\u2705 <b>ACCESS VERIFIED</b>
\u2570\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u256F

\u{1F513} Private decoding is now enabled for your account.
\u{1F4E4} <b>Send your configuration file again to begin.</b>`,
        "HTML"
      );
    } else {
      await sendAccessGate(
        env,
        String(message.chat.id),
        callback.from,
        access.lookupFailed
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
    reply_markup: replyMarkup
  });
}
__name(handleCallbackQuery, "handleCallbackQuery");
__name2(handleCallbackQuery, "handleCallbackQuery");
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
      "This format is not supported yet. Use /help to see the supported extensions."
    );
    return;
  }
  if (document.file_size && document.file_size > MAX_FILE_BYTES) {
    await sendMessage(
      env,
      chatId,
      "That file is too large. The current limit is 8 MiB."
    );
    return;
  }
  const statusMessage = await sendMessage(
    env,
    chatId,
    `\u{1F4E5} <b>UPLOAD RECEIVED</b>
\u2570\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u256F

\u{1F4C4} <b>FILE</b>
\u2514 <code>${escapeHtml(filename)}</code>

\u{1F9E9} <b>FORMAT</b>
\u2514 <b>${escapeHtml(decoderName)}</b>

\u{1F464} <b>REQUESTER</b>
\u2514 ${mentionName(message.from)}

\u26A1 <b>STATUS</b>
\u2514 <i>Analyzing configuration...</i>
\u{1F6E1}\uFE0F <b>Protection:</b> Active`,
    "HTML"
  );
  const cleanupPromise = scheduleStatusMessageDeletion(
    env,
    chatId,
    statusMessage?.message_id
  ).catch((error) => {
    console.error(
      "status cleanup scheduling failed",
      error instanceof Error ? error.message : "unknown error"
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
        chat_type: message.chat?.type || ""
      })
    ]);
  } catch (error) {
    console.error("decode dispatch failed", error instanceof Error ? error.message : "unknown error");
    await sendMessage(
      env,
      chatId,
      "\u26A0\uFE0F I could not submit that file for decoding. Please try again later."
    );
  }
}
__name(handleDocument, "handleDocument");
__name2(handleDocument, "handleDocument");
async function dispatchDecode(env, payload) {
  const response = await fetch(
    `https://api.github.com/repos/${REPOSITORY}/dispatches`,
    {
      method: "POST",
      headers: githubHeaders(env),
      body: JSON.stringify({
        event_type: "decode-config",
        client_payload: payload
      })
    }
  );
  if (!response.ok) {
    throw new Error(`GitHub dispatch failed with HTTP ${response.status}`);
  }
}
__name(dispatchDecode, "dispatchDecode");
__name2(dispatchDecode, "dispatchDecode");
async function telegramRequest(env, method, payload) {
  const response = await fetch(
    `https://api.telegram.org/bot${env.TG_BOT_TOKEN}/${method}`,
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload)
    }
  );
  const data = await response.json().catch(() => null);
  if (!response.ok || !data?.ok) {
    throw new Error(`Telegram ${method} failed with HTTP ${response.status}`);
  }
  return data.result;
}
__name(telegramRequest, "telegramRequest");
__name2(telegramRequest, "telegramRequest");
async function sendMessage(env, chatId, text, parseMode) {
  const payload = { chat_id: chatId, text };
  if (parseMode) payload.parse_mode = parseMode;
  return telegramRequest(env, "sendMessage", payload);
}
__name(sendMessage, "sendMessage");
__name2(sendMessage, "sendMessage");
async function scheduleStatusMessageDeletion(env, chatId, messageId) {
  if (!env.MESSAGE_CLEANUP) {
    throw new Error("MESSAGE_CLEANUP binding is not configured");
  }
  if (!Number.isInteger(messageId)) {
    throw new Error("Telegram did not return a status message ID");
  }
  const deleteAt = Math.floor(Date.now() / 1e3) + STATUS_MESSAGE_TTL_SECONDS;
  const key = `${STATUS_CLEANUP_PREFIX}${deleteAt}:${crypto.randomUUID()}`;
  await env.MESSAGE_CLEANUP.put(
    key,
    JSON.stringify({
      chat_id: String(chatId),
      message_id: messageId,
      delete_at: deleteAt
    }),
    { expirationTtl: STATUS_MESSAGE_TTL_SECONDS + 60 * 60 }
  );
}
__name(scheduleStatusMessageDeletion, "scheduleStatusMessageDeletion");
__name2(scheduleStatusMessageDeletion, "scheduleStatusMessageDeletion");
async function processStatusMessageCleanup(env) {
  if (!env.MESSAGE_CLEANUP) {
    console.error("MESSAGE_CLEANUP binding is not configured");
    return;
  }
  const now = Math.floor(Date.now() / 1e3);
  let cursor;
  do {
    const page = await env.MESSAGE_CLEANUP.list({
      prefix: STATUS_CLEANUP_PREFIX,
      limit: 100,
      ...cursor ? { cursor } : {}
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
        if (!record || !Number.isFinite(record.delete_at) || record.delete_at > now || !record.chat_id || !Number.isInteger(record.message_id)) {
          return;
        }
        try {
          await telegramRequest(env, "deleteMessage", {
            chat_id: record.chat_id,
            message_id: record.message_id
          });
          await env.MESSAGE_CLEANUP.delete(name);
        } catch (error) {
          console.error(
            "status message delete failed",
            error instanceof Error ? error.message : "unknown error"
          );
        }
      })
    );
    cursor = page.list_complete ? void 0 : page.cursor;
  } while (cursor);
}
__name(processStatusMessageCleanup, "processStatusMessageCleanup");
__name2(processStatusMessageCleanup, "processStatusMessageCleanup");
async function sendAccessGate(env, chatId, user, lookupFailed = false) {
  const heading = "\u{1F510} <b>PRIVATE ACCESS REQUIRED</b>";
  const explanation = lookupFailed ? "I could not confirm your channel access right now. Please tap a button above to join." : "To use the decoder in a private chat, join all three ReversalX community destinations below.";
  await telegramRequest(env, "sendMessage", {
    chat_id: chatId,
    text: `${heading}
\u2570\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u256F

${explanation}

1\uFE0F\u20E3 <b>Official Channel 1</b>
2\uFE0F\u20E3 <b>Official Channel 2</b>
3\uFE0F\u20E3 <b>ReversalX Community Group</b>

\u{1F4CC} After joining, tap <b>\u2705 Verify Access</b>.
Once confirmed, I will unlock private decoding and ask you to send your file again.

\u{1F464} Requester: ${mentionName(user)}`,
    parse_mode: "HTML",
    reply_markup: membershipKeyboard()
  });
}
__name(sendAccessGate, "sendAccessGate");
__name2(sendAccessGate, "sendAccessGate");
async function sendCommunityRestriction(env, chatId) {
  await telegramRequest(env, "sendMessage", {
    chat_id: chatId,
    text: `\u{1F6AB} <b>PRIVATE CHAT ONLY</b>
\u2570\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u256F

This bot does not decode files inside groups or channels.

\u{1F510} To use the decoder:
1\uFE0F\u20E3 Join Official Channel 1
2\uFE0F\u20E3 Join Official Channel 2
3\uFE0F\u20E3 Join the ReversalX Community Group

\u{1F4E9} After joining, open a private chat with the bot and tap <b>\u2705 Verify Access</b>.
Your file can only be processed in private chat.`,
    parse_mode: "HTML",
    reply_markup: membershipKeyboard(false)
  });
}
__name(sendCommunityRestriction, "sendCommunityRestriction");
__name2(sendCommunityRestriction, "sendCommunityRestriction");
function githubHeaders(env) {
  return {
    Authorization: `Bearer ${env.GH_TOKEN}`,
    Accept: "application/vnd.github+json",
    "Content-Type": "application/json",
    "User-Agent": "ReversalX-VPN-Decode-Worker/1.0",
    "X-GitHub-Api-Version": "2022-11-28"
  };
}
__name(githubHeaders, "githubHeaders");
__name2(githubHeaders, "githubHeaders");
function welcomeCaption(user = {}, command = "/start") {
  const badgeName = badgeNameFor(user);
  const userId = escapeHtml(String(user.id || "Not provided").slice(0, 64));
  const formats = [...SUPPORTED_FORMATS.entries()].map(([extension, description]) => `\u2022 <code>${extension}</code> \u2014 ${description}`).join("\n");
  const caption = `\u{1F510} <b>ReversalX VPN Decode Bot</b> \u{1F510}

\u{1F44B} Welcome, <b>${badgeName}</b>!

\u{1F9E9} Send a supported VPN configuration file and receive a decrypted readable result.

\u{1F464} <b>Your Session</b>
\u{1F539} User: <b>${badgeName}</b>
\u{1F539} ID: <code>${userId}</code>
\u{1F539} Status: \u2705 Active

\u2728 <b>Supported Formats</b>
${formats}

\u{1F680} <b>How to Use</b>
Send a supported vpn file \u2192 wait \u2192 receive the result.

\u{1F4CC} <b>Commands</b>
/start \u2014 show this welcome
/help \u2014 show formats and usage

\u26A0\uFE0F <i>Only decode files you own or are authorized to inspect.</i>`;
  if (caption.length > 1024) {
    throw new Error(`Telegram caption is too long (${caption.length} characters)`);
  }
  return caption;
}
__name(welcomeCaption, "welcomeCaption");
__name2(welcomeCaption, "welcomeCaption");
function welcomeKeyboard() {
  return {
    inline_keyboard: [
      [{ text: "\u{1F4E2} Join Our Channels \u{1F4E2}", callback_data: "join_channels" }],
      [{ text: "\u{1F465} Join Our Group \u{1F465}", url: GROUP_URL }]
    ]
  };
}
__name(welcomeKeyboard, "welcomeKeyboard");
__name2(welcomeKeyboard, "welcomeKeyboard");
function channelKeyboard(includeVerify = true) {
  const rows = JOIN_BUTTONS.map((button) => [{ ...button }]);
  if (includeVerify) {
    rows.push([{ text: "\u2705 Verify Access", callback_data: "verify_access" }]);
  }
  rows.push([{ text: "\u{1F519} Back \u{1F519}", callback_data: "welcome" }]);
  return { inline_keyboard: rows };
}
__name(channelKeyboard, "channelKeyboard");
__name2(channelKeyboard, "channelKeyboard");
function membershipKeyboard(includeVerify = true) {
  const rows = JOIN_BUTTONS.map((button) => [{ ...button }]);
  if (includeVerify) {
    rows.push([{ text: "\u2705 Verify Access", callback_data: "verify_access" }]);
  }
  return {
    inline_keyboard: rows
  };
}
__name(membershipKeyboard, "membershipKeyboard");
__name2(membershipKeyboard, "membershipKeyboard");
function isPrivateChat(chat) {
  return chat?.type === "private";
}
__name(isPrivateChat, "isPrivateChat");
__name2(isPrivateChat, "isPrivateChat");
function isGroupChat(chat) {
  return chat?.type === "group" || chat?.type === "supergroup";
}
__name(isGroupChat, "isGroupChat");
__name2(isGroupChat, "isGroupChat");
function isChannelChat(chat) {
  return chat?.type === "channel";
}
__name(isChannelChat, "isChannelChat");
__name2(isChannelChat, "isChannelChat");
function isAdminUser(userId) {
  return userId !== void 0 && ADMIN_USER_IDS.has(String(userId));
}
__name(isAdminUser, "isAdminUser");
__name2(isAdminUser, "isAdminUser");
async function checkPrivateAccess(env, userId) {
  if (!userId) return { allowed: false, lookupFailed: true };
  const checks = await Promise.all(
    REQUIRED_MEMBERSHIP_CHAT_IDS.map(async (requiredChatId) => {
      try {
        const member = await telegramRequest(env, "getChatMember", {
          chat_id: requiredChatId,
          user_id: userId
        });
        return { allowed: hasChannelAccess(member), lookupFailed: false };
      } catch (error) {
        console.error(
          "channel membership check failed",
          error instanceof Error ? error.message : "unknown error"
        );
        return { allowed: false, lookupFailed: true };
      }
    })
  );
  return {
    allowed: checks.every((check) => check.allowed),
    lookupFailed: checks.some((check) => check.lookupFailed)
  };
}
__name(checkPrivateAccess, "checkPrivateAccess");
__name2(checkPrivateAccess, "checkPrivateAccess");
function hasChannelAccess(member) {
  if (!member || typeof member.status !== "string") return false;
  if (["creator", "administrator", "member"].includes(member.status)) return true;
  return member.status === "restricted" && member.is_member === true;
}
__name(hasChannelAccess, "hasChannelAccess");
__name2(hasChannelAccess, "hasChannelAccess");
function displayName(user) {
  const fullName = [user.first_name, user.last_name].filter(Boolean).join(" ").trim().slice(0, 48);
  if (fullName) return escapeHtml(fullName);
  const username = String(user.username || "").replace(/^@/, "").slice(0, 48);
  return username ? `@${escapeHtml(username)}` : "there";
}
__name(displayName, "displayName");
__name2(displayName, "displayName");
function badgeNameFor(user) {
  const name = displayName(user).replace(/^(?:🏅\s*)+|(?:\s*🏅)+$/g, "").trim();
  return `\u{1F3C5}${name || "there"}\u{1F3C5}`;
}
__name(badgeNameFor, "badgeNameFor");
__name2(badgeNameFor, "badgeNameFor");
function mentionName(user) {
  const badgeName = badgeNameFor(user);
  if (user?.id) {
    return `<a href="tg://user?id=${escapeHtml(String(user.id))}">${badgeName}</a>`;
  }
  return `<b>${badgeName}</b>`;
}
__name(mentionName, "mentionName");
__name2(mentionName, "mentionName");
function extractCommand(text) {
  if (typeof text !== "string") return "";
  const firstWord = text.trim().split(/\s+/, 1)[0].toLowerCase();
  return firstWord.split("@", 1)[0];
}
__name(extractCommand, "extractCommand");
__name2(extractCommand, "extractCommand");
function safeFilename(value) {
  if (typeof value !== "string") return "";
  const filename = value.trim();
  if (!filename || filename === "." || filename === ".." || filename.includes("/") || filename.includes("\\") || filename.includes("\n") || filename.includes("\r")) {
    return "";
  }
  return filename.slice(0, 180);
}
__name(safeFilename, "safeFilename");
__name2(safeFilename, "safeFilename");
function extensionOf(filename) {
  const dot = filename.lastIndexOf(".");
  return dot >= 0 ? filename.slice(dot).toLowerCase() : "";
}
__name(extensionOf, "extensionOf");
__name2(extensionOf, "extensionOf");
function updateId(message) {
  return String(message.message_id || crypto.randomUUID());
}
__name(updateId, "updateId");
__name2(updateId, "updateId");
function escapeHtml(value) {
  return String(value).replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;").replaceAll('"', "&quot;").replaceAll("'", "&#39;");
}
__name(escapeHtml, "escapeHtml");
__name2(escapeHtml, "escapeHtml");
function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json" }
  });
}
__name(json, "json");
__name2(json, "json");
export {
  worker_default as default
};
//# sourceMappingURL=worker.js.map
