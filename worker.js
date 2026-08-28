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
const LOGO_URL =
  "https://raw.githubusercontent.com/Matrixzat/vpn-decryptor/main/assets/reversalx-vpn-decode-logo.png";
const MAX_FILE_BYTES = 8 * 1024 * 1024;

const SUPPORTED_FORMATS = new Map([
  [".ehi", "HTTP Injector"],
  [".npvt", "NPV Tunnel"],
  [".hc", "HTTP Custom"],
  [".dark", "Dark Tunnel"],
  [".nm", "NetMod"],
  [".tnl", "OpenTunnel OPL v2"],
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
};

async function handleUpdate(update, env) {
  const message = update?.message;
  if (!message?.chat?.id) return;

  const chatId = String(message.chat.id);
  const command = extractCommand(message.text);
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

  await sendMessage(
    env,
    chatId,
    `✅ <b>${escapeHtml(filename)}</b> received.\n\n🔎 Decoder: <b>${escapeHtml(decoderName)}</b>\n⏳ Sending it to the decoder worker...`,
    "HTML",
  );

  try {
    const file = await telegramRequest(env, "getFile", {
      file_id: document.file_id,
    });
    const filePath = file?.file_path;
    if (!filePath) throw new Error("Telegram did not return a file path");

    const download = await fetch(
      `https://api.telegram.org/file/bot${env.TG_BOT_TOKEN}/${encodeURI(filePath)}`,
    );
    if (!download.ok) throw new Error("Telegram file download failed");

    const contentLength = Number(download.headers.get("content-length") || 0);
    if (contentLength > MAX_FILE_BYTES) {
      await sendMessage(env, chatId, "That file is too large. The current limit is 8 MiB.");
      return;
    }

    const bytes = new Uint8Array(await download.arrayBuffer());
    if (bytes.length === 0) throw new Error("The uploaded file is empty");
    if (bytes.length > MAX_FILE_BYTES) {
      await sendMessage(env, chatId, "That file is too large. The current limit is 8 MiB.");
      return;
    }

    const jobId = `${Date.now()}-${updateId(message)}`;
    await dispatchDecode(env, {
      job_id: jobId,
      chat_id: chatId,
      filename,
      file_data_b64: bytesToBase64(bytes),
      first_name: message.from?.first_name || "",
      last_name: message.from?.last_name || "",
      username: message.from?.username || "",
      user_id: String(message.from?.id || ""),
    });
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
  await telegramRequest(env, "sendMessage", payload);
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
  const name = displayName(user);
  const userId = escapeHtml(String(user.id || "Not provided").slice(0, 64));
  const formats = [...SUPPORTED_FORMATS.entries()]
    .map(([extension, description]) => `• <code>${extension}</code> — ${description}`)
    .join("\n");

  const caption = `🔐 <b>ReversalX VPN Decode Bot</b> 🔐

👋 Welcome, <b>${name}</b>!

🧩 Send a supported VPN configuration and receive its readable decrypted result.

👤 <b>Your Session</b>
🔹 User: <b>${name}</b>
🔹 ID: <code>${userId}</code>
🔹 Status: ✅ Active
🔒 Privacy: Files are removed after delivery.

✨ <b>Supported Formats</b>
${formats}

🚀 <b>How to Use</b>
Send a supported file → wait → receive the result.

📌 <b>Commands</b>
/start — show this welcome
/help — show formats and usage

⚠️ <i>Only decode files you own or are authorized to inspect.</i>`;

  if (caption.length > 1024) {
    throw new Error(`Telegram caption is too long (${caption.length} characters)`);
  }
  return caption;
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

function bytesToBase64(bytes) {
  let output = "";
  const chunkSize = 0x8000;
  for (let index = 0; index < bytes.length; index += chunkSize) {
    output += String.fromCharCode(...bytes.subarray(index, index + chunkSize));
  }
  return btoa(output);
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