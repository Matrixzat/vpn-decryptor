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
  [".v2box", "V2Box / V2Ray export"]
]);
// Exact union of the uploaded 239-suffix catalog and the additional .solid port.
// scripts/verify_import.py checks this list against the engine, not just the README.
var SPDECODE_SUFFIXES = "1300 4ulite 7net ace acm act actun actunnelvpn agn ai aip aipr aloplusvpn apnalite apnatnl ar aro at aura bbb bcl bdi bdnet bee bshield btv cbp ccc cer cerv cks clay cln cloudy cly cnet cranetunnel crev cyber cyh dak dark ddd deep deshtunnelvpn dev dkarl dvd dzd ec edan eee ehi ehil ena epro eta etun eug eut ezi fix fks flex flexnet flynet flynetvpn fnet fnf fnnetwork fthp ftp ftr fɴ garuda gcpvpn gibs glory gold grd great gv hamotunnelplus hat hbd hc hdb hq hqp hrt hsome ht hta htb htp hub hxt ignix_vpn int ipt it itv izph jez jph juan juanscript jvc jvi kt ktr letsvpngo lnk lt ltm lucky marvs max maya mc md mdp mdproxy mdvpn mehaf mhrtunnel mij mina mm mmt mobi mrc msy mtl mtv2ray mtv2raypro n4 nac nd4 net nhi nm npv2 npv4 npvs npvt nt ntr nur nurtunnel nx nxp omanova osp ost osv pausa pb pcx phc pin pir pkm purple pxp rez rezl roy ry safetunnel sbr sds sip sks sksplus sksrv sksrv.png sksx skvoid sky slipnet solid spd ssc ssh sshbrasil ssi st stk sut t10 t20 tcv2 tcx temt tik tiktunnel tito tls tmt tnl tpp tsd tsm tut tvt tx ulti ultra ultratunnel ursa ut utn uwu v2 v2box v2i vel vipsnipherpro vlx vmx vn7 vpc vpnlite wcm wolf wolftunnel wrld wt wyr wyrl wyrlite wyrvpnlite xhypher xscks xsks xtp xui ziv zoba".split(" ");
var PORT_FORMAT_NAMES = {
  "1300": "Generic AES-GCM / PBKDF2",
  "4ulite": "XOR VPN family",
  "7net": "RENZ / 7NET",
  "ace": "Generic AES-GCM / PBKDF2",
  "acm": "Generic DES-ECB (AES-GCM fallback)",
  "act": "Generic AES-GCM / PBKDF2",
  "actun": "RENZ / ACTUNNELVPN",
  "actunnelvpn": "RENZ / ACTUNNELVPN",
  "agn": "AGN Injector",
  "ai": "Generic AES-GCM / PBKDF2",
  "aip": "Generic AES-GCM / PBKDF2",
  "aipr": "Generic AES-GCM / PBKDF2",
  "aloplusvpn": "RENZ / ALOPLUSVPN",
  "apnalite": "XOR VPN family",
  "apnatnl": "XOR VPN family",
  "ar": "AR Pro / MSY",
  "aro": "ARMOD",
  "at": "ASH tunnel",
  "aura": "AURA TUNNEL",
  "bbb": "Generic AES-GCM / PBKDF2",
  "bcl": "BCL TUNNEL",
  "bdi": "Generic AES-GCM / PBKDF2",
  "bdnet": "XOR VPN family",
  "bee": "BEE TUNNEL",
  "bshield": "RENZ / BSHIELD",
  "btv": "BTV TUNNEL",
  "cbp": "Generic AES-GCM / PBKDF2",
  "ccc": "Generic AES-GCM / PBKDF2",
  "cer": "CREV",
  "cerv": "CREV",
  "cks": "Generic AES-GCM / PBKDF2",
  "clay": "Generic DES-ECB (AES-GCM fallback)",
  "cln": "Generic AES-GCM / PBKDF2",
  "cloudy": "Cloudy Inject",
  "cly": "Cloudy",
  "cnet": "Generic AES-GCM / PBKDF2",
  "cranetunnel": "RENZ / CRANETUNNEL",
  "crev": "CREV",
  "cyber": "Generic AES-GCM / PBKDF2",
  "cyh": "Generic AES-GCM / PBKDF2",
  "dak": "Generic DES-ECB (AES-GCM fallback)",
  "dark": "Dark Tunnel",
  "ddd": "Generic AES-GCM / PBKDF2",
  "deep": "DEEP TUNNEL",
  "deshtunnelvpn": "RENZ / DESHTUNNELVPN",
  "dev": "DEV VPN",
  "dkarl": "Generic AES-GCM / PBKDF2",
  "dvd": "Generic AES-GCM / PBKDF2",
  "dzd": "Generic AES-GCM / PBKDF2",
  "ec": "EC Tunnel",
  "edan": "Generic AES-GCM / PBKDF2",
  "eee": "Generic AES-GCM / PBKDF2",
  "ehi": "HTTP Injector",
  "ehil": "HTTP Injector Lite",
  "ena": "ENA TUNNEL",
  "epro": "ePro Tunnel",
  "eta": "ETA TUNNEL",
  "etun": "Generic AES-GCM / PBKDF2",
  "eug": "Generic AES-GCM / PBKDF2",
  "eut": "EUT Tunnel",
  "ezi": "Generic AES-GCM / PBKDF2",
  "fix": "FIX TUNNEL",
  "fks": "Generic AES-GCM / PBKDF2",
  "flex": "FlexNet",
  "flexnet": "FlexNet",
  "flynet": "FLY NET VPN",
  "flynetvpn": "FLY NET VPN",
  "fnet": "Generic AES-GCM / PBKDF2",
  "fnf": "XOR VPN family",
  "fnnetwork": "FN Network",
  "fthp": "FTHP",
  "ftp": "FTHP",
  "ftr": "Generic DES-ECB (AES-GCM fallback)",
  "fɴ": "FN Tunnel",
  "garuda": "Generic AES-GCM / PBKDF2",
  "gcpvpn": "RENZ / GCPVPN",
  "gibs": "Generic AES-GCM / PBKDF2",
  "glory": "GLORY TUNNEL",
  "gold": "Gold Tunnel",
  "grd": "Generic AES-GCM / PBKDF2",
  "great": "GREAT TUNNEL",
  "gv": "Generic AES-GCM / PBKDF2",
  "hamotunnelplus": "RENZ / HAMOTUNNELPLUS",
  "hat": "HA Tunnel Plus",
  "hbd": "Generic AES-GCM / PBKDF2",
  "hc": "HTTP Custom",
  "hdb": "Generic AES-GCM / PBKDF2",
  "hq": "Generic AES-GCM / PBKDF2",
  "hqp": "Generic AES-GCM / PBKDF2",
  "hrt": "HRT Tunnel",
  "hsome": "XOR VPN family",
  "ht": "HTTP Tweak",
  "hta": "Generic AES-GCM / PBKDF2",
  "htb": "HTTP Tweak",
  "htp": "Generic DES-ECB (AES-GCM fallback)",
  "hub": "Generic AES-GCM / PBKDF2",
  "hxt": "XOR VPN family",
  "ignix_vpn": "Generic AES-GCM / PBKDF2",
  "int": "IntVPN",
  "ipt": "WeTunnel",
  "it": "Generic DES-ECB (AES-GCM fallback)",
  "itv": "ITV Tunnel",
  "izph": "IZPH VPN Pro",
  "jez": "JEZ Tunnel",
  "jph": "Generic AES-GCM / PBKDF2",
  "juan": "JuanScript",
  "juanscript": "JuanScript",
  "jvc": "JVC Tunnel",
  "jvi": "JVI Tunnel",
  "kt": "Generic AES-GCM / PBKDF2",
  "ktr": "KTR",
  "letsvpngo": "RENZ / LETSVPNGO",
  "lnk": "LinkLayer VPN",
  "lt": "LTM Tunnel",
  "ltm": "LTM Tunnel",
  "lucky": "LUCKY PROXY",
  "marvs": "MARVS TUNNEL",
  "max": "Generic AES-GCM / PBKDF2",
  "maya": "Maya Tunnel",
  "mc": "Generic AES-GCM / PBKDF2",
  "md": "MD TUNNEL",
  "mdp": "MD PROXY VPN",
  "mdproxy": "MD PROXY VPN",
  "mdvpn": "MD VPN",
  "mehaf": "MEHAF TUNNEL",
  "mhrtunnel": "RENZ / MHRTUNNEL",
  "mij": "MIJ Tunnel",
  "mina": "MinaProNet",
  "mm": "MM TUNNEL",
  "mmt": "MMT TUNNEL",
  "mobi": "JuanScript",
  "mrc": "MRC Tunnel",
  "msy": "AR Pro / MSY",
  "mtl": "MTL Tunnel",
  "mtv2ray": "MT V2RAY",
  "mtv2raypro": "MT V2RAY PRO",
  "n4": "N4 VPN Pro",
  "nac": "Generic AES-GCM / PBKDF2",
  "nd4": "Generic AES-GCM / PBKDF2",
  "net": "Generic AES-GCM / PBKDF2",
  "nhi": "Generic AES-GCM / PBKDF2",
  "nm": "NetMod",
  "npv2": "NPV Tunnel v2",
  "npv4": "NPV Tunnel v4",
  "npvs": "NPV Tunnel NPVS v5",
  "npvt": "NPV Tunnel v4",
  "nt": "Net Tunnel",
  "ntr": "Generic AES-GCM / PBKDF2",
  "nur": "NUR TUNNEL",
  "nurtunnel": "NUR TUNNEL",
  "nx": "Generic AES-GCM / PBKDF2",
  "nxp": "Generic DES-ECB (AES-GCM fallback)",
  "omanova": "XOR VPN family",
  "osp": "RENZ / 7NET",
  "ost": "OUSS Tunnel",
  "osv": "OSV TUNNEL",
  "pausa": "Generic AES-GCM / PBKDF2",
  "pb": "XrayPB",
  "pcx": "PCX Tunnel",
  "phc": "PHC Tunnel",
  "pin": "Generic DES-ECB (AES-GCM fallback)",
  "pir": "Generic AES-GCM / PBKDF2",
  "pkm": "Generic AES-GCM / PBKDF2",
  "purple": "Generic AES-GCM / PBKDF2",
  "pxp": "Generic AES-GCM / PBKDF2",
  "rez": "Rez Tunnel",
  "rezl": "Rez Tunnel Lite",
  "roy": "Royal Tunnel",
  "ry": "RY TUNNEL",
  "safetunnel": "RENZ / SAFETUNNEL",
  "sbr": "SBR Injector",
  "sds": "Generic AES-GCM / PBKDF2",
  "sip": "SocksIP / SocksTunnel",
  "sks": "SocksHTTP",
  "sksplus": "SocksIP Plus",
  "sksrv": "SKS Server",
  "sksrv.png": "SKS Server",
  "sksx": "Generic AES-GCM / PBKDF2",
  "skvoid": "Generic AES-GCM / PBKDF2",
  "sky": "Generic AES-GCM / PBKDF2",
  "slipnet": "SlipNet",
  "solid": "NUR Tunnel",
  "spd": "Generic AES-GCM / PBKDF2",
  "ssc": "SSC Custom",
  "ssh": "SSH Injector",
  "sshbrasil": "Generic AES-GCM / PBKDF2",
  "ssi": "Generic AES-GCM / PBKDF2",
  "st": "Sentinel Tunnel",
  "stk": "Stark VPN",
  "sut": "SUT Tunnel",
  "t10": "T10 TUNNEL",
  "t20": "T20 TUNNEL",
  "tcv2": "Generic AES-GCM / PBKDF2",
  "tcx": "RENZ / TCXTUNNEL",
  "temt": "Generic AES-GCM / PBKDF2",
  "tik": "TIK TUNNEL",
  "tiktunnel": "TIK TUNNEL",
  "tito": "Generic AES-GCM / PBKDF2",
  "tls": "TLS Tunnel",
  "tmt": "Generic AES-GCM / PBKDF2",
  "tnl": "OpenTunnel",
  "tpp": "Generic AES-GCM / PBKDF2",
  "tsd": "Generic AES-GCM / PBKDF2",
  "tsm": "TSM TUNNEL",
  "tut": "Generic DES-ECB (AES-GCM fallback)",
  "tvt": "TV Tunnel",
  "tx": "TX TUNNEL",
  "ulti": "ULTI TUNNEL",
  "ultra": "ULTRA TUNNEL",
  "ultratunnel": "ULTRA TUNNEL",
  "ursa": "XOR VPN family",
  "ut": "ULTRA TUNNEL",
  "utn": "Generic AES-GCM / PBKDF2",
  "uwu": "UWU Tunnel",
  "v2": "e-V2Ray",
  "v2box": "V2Box Export",
  "v2i": "V2Ray Injector",
  "vel": "VEL TUNNEL",
  "vipsnipherpro": "RENZ / VIPSNIPHERPRO",
  "vlx": "VLX TUNNEL",
  "vmx": "Generic DES-ECB (AES-GCM fallback)",
  "vn7": "VN7",
  "vpc": "Generic DES-ECB (AES-GCM fallback)",
  "vpnlite": "VPN Lite",
  "wcm": "Generic AES-GCM / PBKDF2",
  "wolf": "WOLF TUNNEL",
  "wolftunnel": "WOLF TUNNEL",
  "wrld": "Generic DES-ECB (AES-GCM fallback)",
  "wt": "Generic AES-GCM / PBKDF2",
  "wyr": "WyrVPN",
  "wyrl": "WyrLite",
  "wyrlite": "WyrLite",
  "wyrvpnlite": "WyrLite",
  "xhypher": "RENZ / XHYPHER",
  "xscks": "X-Socks",
  "xsks": "Generic DES-ECB (AES-GCM fallback)",
  "xtp": "XTProy",
  "xui": "XUI Tunnel",
  "ziv": "ZIVPN",
  "zoba": "Zoba VPN"
};
function publicFormatName(suffix, catalogName) {
  // Unnamed catalog families use their format alias, never implementation labels.
  if (/\b(?:generic|aes|des|pbkdf\d*|xor|gcm|cbc|ecb|argon2|chacha20|salsa20|xxtea)\b/i.test(catalogName)) {
    return suffix.toUpperCase();
  }
  return catalogName.replace(/^RENZ\s*\/\s*/i, "").replace(/\s+Export$/, "");
}
for (const suffix of SPDECODE_SUFFIXES) {
  if (!PORT_FORMAT_NAMES[suffix]) throw new Error(`Missing format name: ${suffix}`);
  SUPPORTED_FORMATS.set("." + suffix, publicFormatName(suffix, PORT_FORMAT_NAMES[suffix]));
}
var FORMAT_DECODER_COUNT = 77;
var FORMAT_PAGE_SIZE = 90;
var FORMAT_SEARCH_PROMPT = "🔎 Search Supported Formats";
var FORMAT_ENTRIES = [...SUPPORTED_FORMATS].map(([extension, name]) => ({ extension, name }))
  .sort((a, b) => a.name.localeCompare(b.name) || a.extension.localeCompare(b.extension))
  .map((entry, id) => ({ ...entry, id }));
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
  // The catalog is public; only decoding stays behind the membership gate.
  if (command === "/formats") {
    const query = normalizeFormatQuery(message.text.replace(/^\s*\/formats(?:@\S+)?\s*/i, ""));
    await sendFormats(env, chatId, { query });
    return;
  }
  if (isFormatSearchReply(message, env)) {
    await sendFormats(env, chatId, { query: command === "/cancel" ? "" : normalizeFormatQuery(message.text) });
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
      "Send a supported configuration file, use /help for usage, or /formats for the complete format list."
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
function normalizeFormatQuery(value) {
  if (typeof value !== "string") return "";
  return [...value.replace(/[\u0000-\u001f\u007f]/g, " ").trim()].slice(0, 80).join("");
}
function formatQueryFromMessage(message) {
  return normalizeFormatQuery((message?.text || "").match(/^Search: (.*)$/m)?.[1] || "");
}
function matchingFormats(query) {
  const terms = query.normalize("NFKC").toLowerCase().replace(/^\./, "").split(/\s+/).filter(Boolean);
  return FORMAT_ENTRIES.filter(entry => {
    const haystack = `${entry.name} ${entry.extension}`.normalize("NFKC").toLowerCase();
    return terms.every(term => haystack.includes(term));
  });
}
function formatsPage(page = 0, query = "") {
  query = normalizeFormatQuery(query);
  const matches = matchingFormats(query);
  const pages = Math.max(1, Math.ceil(matches.length / FORMAT_PAGE_SIZE));
  page = Math.max(0, Math.min(pages - 1, Number.isSafeInteger(page) ? page : 0));
  const start = page * FORMAT_PAGE_SIZE;
  const shown = matches.slice(start, start + FORMAT_PAGE_SIZE);
  const rows = shown.map(entry => [{
    text: `${entry.name} · ${entry.extension}`,
    callback_data: `formats:detail:${entry.id}:${page}`
  }]);
  if (matches.length) {
    const navigation = [];
    if (page > 0) navigation.push({ text: "‹ Previous", callback_data: `formats:page:${page - 1}` });
    navigation.push({ text: `Page ${page + 1} / ${pages}`, callback_data: "formats:info" });
    if (page + 1 < pages) navigation.push({ text: "Next ›", callback_data: `formats:page:${page + 1}` });
    rows.push(navigation);
  }
  rows.push([
    { text: "🔎 Search", callback_data: "formats:search" },
    { text: "📚 All Formats", callback_data: "formats:all" }
  ]);
  rows.push([{ text: "🏠 Main Menu", callback_data: "formats:menu" }]);
  const text = `🪀 <b>SUPPORTED FORMATS</b> 🪀

<b>${FORMAT_DECODER_COUNT} decoders</b> · <b>${FORMAT_ENTRIES.length} supported extensions</b>
${query ? `\nSearch: ${escapeHtml(query)}\n<b>${matches.length} matching formats</b>\n` : ""}
${matches.length ? `Showing <b>${start + 1}–${start + shown.length}</b> of <b>${matches.length}</b> · Page <b>${page + 1}/${pages}</b>

Tap an app below for its full name and extension.
Use Previous / Next to browse the rest.` : "No matching formats found. Tap Search to try another app name or extension."}

<i>Some apps support more than one extension.</i>`;
  return { text, parse_mode: "HTML", reply_markup: { inline_keyboard: rows } };
}
async function sendFormats(env, chatId, { page = 0, query = "", messageId = null } = {}) {
  const payload = { chat_id: chatId, ...formatsPage(page, query) };
  if (messageId) {
    payload.message_id = messageId;
    try {
      await telegramRequest(env, "editMessageText", payload);
    } catch (error) {
      // Repeated taps on the current page are an acknowledged, harmless no-op.
      if (!(error instanceof Error && error.message.includes("message is not modified"))) throw error;
    }
  } else {
    await telegramRequest(env, "sendMessage", payload);
  }
}
function isFormatSearchReply(message, env) {
  const replied = message.reply_to_message;
  const botId = env.TG_BOT_TOKEN.split(":")[0];
  return Boolean(message.text && replied?.from?.is_bot && String(replied.from.id) === botId
    && replied.text?.startsWith(FORMAT_SEARCH_PROMPT));
}
async function handleFormatCallback(callback, env) {
  const message = callback.message;
  const chatId = String(message.chat.id);
  const data = callback.data;
  const query = formatQueryFromMessage(message);
  if (data === "formats:open" || data === "formats:all") {
    await sendFormats(env, chatId, { messageId: data === "formats:all" ? message.message_id : null });
  } else if (/^formats:page:\d{1,7}$/.test(data)) {
    await sendFormats(env, chatId, { page: Number(data.split(":")[2]), query, messageId: message.message_id });
  } else if (/^formats:detail:\d{1,3}:\d{1,7}$/.test(data)) {
    const [, , id, page] = data.split(":");
    const entry = FORMAT_ENTRIES[Number(id)];
    if (!entry) return;
    await telegramRequest(env, "editMessageText", {
      chat_id: chatId, message_id: message.message_id, parse_mode: "HTML",
      text: `🧩 <b>FORMAT DETAILS</b>\n\n<b>App / format name</b>\n${escapeHtml(entry.name)}\n\n<b>Extension</b>\n<code>${escapeHtml(entry.extension)}</code>\n\nSend a ${escapeHtml(entry.extension)} file to decode it.${query ? `\n\nSearch: ${escapeHtml(query)}` : ""}`,
      reply_markup: { inline_keyboard: [
        [{ text: "‹ Back to Formats", callback_data: `formats:page:${page}` }],
        [{ text: "🔎 Search", callback_data: "formats:search" }, { text: "📚 All Formats", callback_data: "formats:all" }]
      ] }
    });
  } else if (data === "formats:search") {
    await telegramRequest(env, "sendMessage", {
      chat_id: chatId, parse_mode: "HTML",
      text: `${FORMAT_SEARCH_PROMPT}\n\nReply with an <b>app name or extension</b>, such as <code>NPV</code>, <code>.tls</code>, or <code>HTTP Custom</code>.\n\nUse /cancel to return to all formats.\n\nRequested by ${mentionName(callback.from)}.`,
      reply_markup: { force_reply: true, selective: true, input_field_placeholder: "App name or extension…" }
    });
  } else if (data === "formats:menu") {
    await sendWelcome(env, chatId, callback.from, "/start");
  }
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
  if (callback.data === "formats:info") {
    callbackAnswer.text = `${FORMAT_DECODER_COUNT} decoders • ${FORMAT_ENTRIES.length} supported extensions. Use Previous / Next to browse.`;
  }
  await telegramRequest(env, "answerCallbackQuery", callbackAnswer);
  const message = callback.message;
  if (!message?.chat?.id || !message.message_id) return;
  if (typeof callback.data === "string" && callback.data.startsWith("formats:")) {
    await handleFormatCallback(callback, env);
    return;
  }
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
      "This format is not supported yet. Use /formats to see every supported extension."
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
  const caption = `\u{1F510} <b>ReversalX VPN Decode Bot</b> \u{1F510}

\u{1F44B} Welcome, <b>${badgeName}</b>!

\u{1F9E9} Send a supported VPN configuration file and receive a decrypted readable result.

\u{1F464} <b>Your Session</b>
\u{1F539} User: <b>${badgeName}</b>
\u{1F539} ID: <code>${userId}</code>
\u{1F539} Status: \u2705 Active

\u2728 <b>Supported Formats</b>
<b>${FORMAT_DECODER_COUNT} decoders · ${SUPPORTED_FORMATS.size} formats</b>
Tap <b>🪀 Supported Formats 🪀</b> below to browse every app and extension, or search for one.

\u{1F680} <b>How to Use</b>
Send a supported vpn file \u2192 wait \u2192 receive the result.

\u{1F4CC} <b>Commands</b>
/start \u2014 show this welcome
/help \u2014 show usage
/formats \u2014 list every supported format

\u26A0\uFE0F <i>Only decode files you own or are authorized to inspect.</i>`;
  const visibleCaption = caption.replace(/<[^>]*>/g, "").replace(/&(?:amp|lt|gt|quot|#39);/g, "x");
  if (visibleCaption.length > 1024) {
    throw new Error(`Telegram caption is too long (${visibleCaption.length} visible characters)`);
  }
  return caption;
}
__name(welcomeCaption, "welcomeCaption");
__name2(welcomeCaption, "welcomeCaption");
function welcomeKeyboard() {
  return {
    inline_keyboard: [
      [{ text: "\u{1F4E2} Join Our Channels \u{1F4E2}", callback_data: "join_channels" }],
      [{ text: "\u{1F465} Join Our Group \u{1F465}", url: GROUP_URL }],
      [{ text: "🪀 Supported Formats 🪀", callback_data: "formats:open" }]
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
  const lower = filename.toLowerCase();
  // Choose .sksrv.png before .png; match the Python engine's routing exactly.
  const supported = [...SUPPORTED_FORMATS.keys()].sort((a, b) => b.length - a.length);
  for (const extension of supported) {
    if (lower.endsWith(extension)) return extension;
  }
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
