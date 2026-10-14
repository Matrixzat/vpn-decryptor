import { readFileSync } from "node:fs";
import assert from "node:assert/strict";
import test from "node:test";

const source = readFileSync(new URL("../worker.js", import.meta.url), "utf8");
const { default: worker } = await import("data:text/javascript;base64," + Buffer.from(source).toString("base64"));
const suffixes = source.match(/var SPDECODE_SUFFIXES = "([^"]+)"/)[1].split(" ");
const catalog = JSON.parse(readFileSync(new URL("../vendor/spdecode_python/spdecode/data/decoder_catalog.json", import.meta.url), "utf8")).entries;
const decoderIndex = JSON.parse(readFileSync(new URL("../vendor/spdecode_python/decoder_index.json", import.meta.url), "utf8"));
const expectedNames = new Map(catalog.map(entry => [entry.suffix, entry.name]));
for (const [suffix, name] of Object.entries({ solid: "NUR Tunnel", sip: "SocksIP / SocksTunnel", sks: "SocksHTTP", tnl: "OpenTunnel" })) {
  expectedNames.set(suffix, name);
}
for (const [suffix, name] of expectedNames) {
  expectedNames.set(suffix, /\b(?:generic|aes|des|pbkdf\d*|xor|gcm|cbc|ecb|argon2|chacha20|salsa20|xxtea)\b/i.test(name)
    ? suffix.toUpperCase() : name.replace(/^RENZ\s*\/\s*/i, "").replace(/\s+Export$/, ""));
}
const technicalLabels = /\b(?:generic|aes|des|pbkdf\d*|xor|gcm|cbc|ecb|argon2|chacha20|salsa20|xxtea|fallback|renz)\b/i;
const env = {
  TG_BOT_TOKEN: "999999:synthetic-test-token",
  TG_WEBHOOK_SECRET: "synthetic-test-secret",
  GH_TOKEN: "synthetic-test-token",
  MESSAGE_CLEANUP: { async put() {} }
};

async function invoke(update, { secret = env.TG_WEBHOOK_SECRET, chatType = "private", userId = 853645999 } = {}) {
  const calls = [];
  globalThis.fetch = async (url, options) => {
    const body = JSON.parse(options.body);
    calls.push({ url: String(url), body });
    if (String(url).startsWith("https://api.github.com/")) return new Response(null, { status: 204 });
    const method = String(url).split("/").at(-1);
    const result = method === "getChatMember" ? { status: "member" } : { message_id: calls.length };
    return Response.json({ ok: true, result });
  };
  const message = { chat: { id: 100, type: chatType }, from: { id: userId, first_name: "Synthetic" }, message_id: 1, ...update };
  const promises = [];
  const response = await worker.fetch(new Request("https://worker.example/telegram/webhook", {
    method: "POST",
    headers: { "Content-Type": "application/json", "X-Telegram-Bot-Api-Secret-Token": secret },
    body: JSON.stringify(update.callback_query ? update : { message })
  }), env, { waitUntil(promise) { promises.push(promise); } });
  await Promise.all(promises);
  return { calls, response };
}

function plainText(html) {
  return html.replace(/<[^>]*>/g, "").replace(/&(amp|lt|gt|quot|#39);/g,
    (_, entity) => ({ amp: "&", lt: "<", gt: ">", quot: '"', "#39": "'" })[entity]);
}
function buttons(body) {
  return body.reply_markup.inline_keyboard.flat();
}
function formatButtons(body) {
  return buttons(body).filter(button => button.callback_data?.startsWith("formats:detail:"));
}
function sentBody(result, method = "sendMessage") {
  const call = result.calls.find(call => call.url.endsWith("/" + method));
  assert.ok(call, `Expected ${method}`);
  return call.body;
}
async function press(data, body = {}, overrides = {}) {
  return invoke({ callback_query: {
    id: "synthetic-callback", data, from: { id: 853645999, first_name: "Synthetic" },
    message: { chat: { id: 100, type: "private" }, message_id: 10, text: plainText(body.text || ""), ...overrides }
  } });
}

test("rejects an invalid webhook secret without API calls", async () => {
  const { calls, response } = await invoke({ text: "/start" }, { secret: "invalid" });
  assert.equal(response.status, 401);
  assert.equal(calls.length, 0);
});

test("accepts every imported suffix, including compound and Unicode names", async () => {
  assert.equal(new Set(suffixes).size, 240);
  for (const suffix of suffixes) {
    const filename = "SAMPLE." + suffix.toUpperCase();
    const { calls, response } = await invoke({
      document: { file_name: filename, file_size: 256, file_id: "synthetic-file-id" }
    });
    assert.equal(response.status, 200);
    const dispatches = calls.filter(call => call.url.startsWith("https://api.github.com/"));
    assert.equal(dispatches.length, 1, suffix);
    assert.equal(dispatches[0].body.event_type, "decode-config");
    assert.equal(dispatches[0].body.client_payload.filename, filename);
    assert.equal(dispatches[0].body.client_payload.telegram_file_id, "synthetic-file-id");
  }
});

test("rejects oversized, unsupported, and path-containing uploads", async () => {
  for (const document of [
    { file_name: "config.npvs", file_size: 8 * 1024 * 1024 + 1 },
    { file_name: "config.exe", file_size: 128 },
    { file_name: "../config.tls", file_size: 128 }
  ]) {
    const { calls } = await invoke({ document: { ...document, file_id: "synthetic" } });
    assert.equal(calls.filter(call => call.url.startsWith("https://api.github.com/")).length, 0);
  }
});

test("inline pagination exposes all 240 correctly named extensions within button limits", async () => {
  let body = sentBody(await invoke({ text: "/formats" }));
  const advertised = new Map();
  const sizes = [];
  assert.equal(decoderIndex.length, 77);
  for (;;) {
    assert.ok(body.text.includes("77 decoders"));
    assert.ok(body.text.includes("240 supported extensions"));
    assert.ok(body.text.length < 4096);
    assert.ok(buttons(body).length <= 100);
    assert.ok(body.reply_markup.inline_keyboard.every(row => row.length <= 8));
    for (const button of buttons(body)) {
      assert.ok(Buffer.byteLength(button.callback_data) <= 64);
      assert.ok(!technicalLabels.test(button.text), button.text);
    }
    const rows = formatButtons(body);
    sizes.push(rows.length);
    for (const button of rows) {
      const [name, extension] = button.text.split(" · ");
      const suffix = extension.slice(1);
      assert.equal(name, expectedNames.get(suffix), suffix);
      assert.ok(!advertised.has(suffix), `Duplicate extension ${suffix}`);
      advertised.set(suffix, name);
      const detail = sentBody(await press(button.callback_data, body), "editMessageText");
      assert.ok(detail.text.includes(`<code>${extension}</code>`));
      assert.ok(detail.text.includes(name));
      assert.ok(!technicalLabels.test(detail.text), detail.text);
    }
    const next = buttons(body).find(button => button.text === "Next ›");
    if (!next) break;
    body = sentBody(await press(next.callback_data, body), "editMessageText");
  }
  assert.deepEqual(sizes, [90, 90, 60]);
  assert.deepEqual([...advertised.keys()].sort(), [...suffixes].sort());
});

test("welcome caption stays within its visible limit with escaped names", async () => {
  const { calls } = await invoke({
    text: "/start",
    from: { id: 853645999, first_name: "<&>".repeat(16) }
  });
  const photo = calls.find(call => call.url.endsWith("/sendPhoto"));
  assert.ok(photo, "The welcome must not fail silently");
  const visible = photo.body.caption.replace(/<[^>]*>/g, "").replace(/&(?:amp|lt|gt|quot|#39);/g, "x");
  assert.ok(visible.length <= 1024);
  assert.ok(photo.body.caption.includes("/formats"));
  assert.ok(photo.body.caption.includes("240 formats"));
  assert.ok(photo.body.caption.includes("77 decoders"));
  assert.ok(!technicalLabels.test(photo.body.caption));
  const keyboard = buttons(photo.body);
  assert.ok(keyboard.some(button => button.callback_data === "join_channels"));
  assert.ok(keyboard.some(button => button.url));
  assert.deepEqual(keyboard.at(-1), { text: "🪀 Supported Formats 🪀", callback_data: "formats:open" });
});

test("welcome format button opens a new browser without editing a photo caption", async () => {
  const result = await press("formats:open", {}, { photo: [{ file_id: "synthetic" }] });
  assert.ok(result.calls.some(call => call.url.endsWith("/answerCallbackQuery")));
  assert.equal(result.calls.filter(call => call.url.endsWith("/editMessageText")).length, 0);
  assert.equal(formatButtons(sentBody(result)).length, 90);
});

test("previous/next boundaries, page info, reset, and main menu work", async () => {
  const first = sentBody(await invoke({ text: "/formats" }));
  assert.ok(!buttons(first).some(button => button.text === "‹ Previous"));
  const second = sentBody(await press("formats:page:1", first), "editMessageText");
  assert.ok(buttons(second).some(button => button.text === "‹ Previous"));
  const restored = sentBody(await press("formats:page:0", second), "editMessageText");
  assert.deepEqual(formatButtons(restored), formatButtons(first));
  const last = sentBody(await press("formats:page:9999999", first), "editMessageText");
  assert.equal(formatButtons(last).length, 60);
  assert.ok(!buttons(last).some(button => button.text === "Next ›"));
  const reset = sentBody(await press("formats:all", last), "editMessageText");
  assert.deepEqual(formatButtons(reset), formatButtons(first));
  const info = await press("formats:info", first);
  assert.equal(info.calls.length, 1);
  assert.ok(info.calls[0].body.text.includes("77 decoders"));
  const menu = sentBody(await press("formats:menu", first), "sendPhoto");
  assert.ok(buttons(menu).some(button => button.callback_data === "formats:open"));
});

test("search button prompts a selective reply and searches app names or extensions", async () => {
  const browser = sentBody(await invoke({ text: "/formats" }));
  const prompt = sentBody(await press("formats:search", browser));
  assert.equal(prompt.reply_markup.force_reply, true);
  assert.equal(prompt.reply_markup.selective, true);
  assert.ok(prompt.text.includes("tg://user?id=853645999"));
  const reply = { from: { id: 999999, is_bot: true }, text: plainText(prompt.text) };
  for (const [query, wanted] of [[".NPVS", ["npvs"]], ["hTtP cUsToM", ["hc"]], ["Fɴ", ["fɴ"]]]) {
    const result = await invoke({ text: query, reply_to_message: reply }, { userId: 12345 });
    const body = sentBody(result);
    assert.deepEqual(formatButtons(body).map(button => button.text.split(" · .")[1]), wanted);
    assert.equal(result.calls.filter(call => call.url.endsWith("/getChatMember")).length, 0);
  }
  const canceled = sentBody(await invoke({ text: "/cancel", reply_to_message: reply }));
  assert.equal(formatButtons(canceled).length, 90);
  const spoof = await invoke({ text: ".tls", reply_to_message: { ...reply, from: { id: 888888, is_bot: true } } });
  assert.ok(!sentBody(spoof).text.includes("SUPPORTED FORMATS"));
});

test("search state survives next, details, and back without storing users' queries", async () => {
  const first = sentBody(await invoke({ text: "/formats@ExampleBot t" }));
  assert.ok(first.text.includes("Search: t"));
  const next = buttons(first).find(button => button.text === "Next ›");
  assert.ok(next);
  const second = sentBody(await press(next.callback_data, first), "editMessageText");
  assert.ok(second.text.includes("Search: t"));
  const selected = formatButtons(second)[0];
  const detail = sentBody(await press(selected.callback_data, second), "editMessageText");
  assert.ok(detail.text.includes("Search: t"));
  const back = sentBody(await press(buttons(detail)[0].callback_data, detail), "editMessageText");
  assert.deepEqual(formatButtons(back), formatButtons(second));
  const reset = sentBody(await press("formats:all", back), "editMessageText");
  assert.ok(!reset.text.includes("Search:"));
  assert.equal(formatButtons(reset).length, 90);
});

test("empty results, special-character searches, and long queries remain safe", async () => {
  for (const query of ["not-a-real-app", "<b>&🤡".repeat(100)]) {
    const body = sentBody(await invoke({ text: "/formats " + query }));
    assert.equal(formatButtons(body).length, 0);
    assert.ok(body.text.includes("No matching formats"));
    assert.ok(buttons(body).some(button => button.callback_data === "formats:search"));
    assert.ok(body.text.length < 4096);
    assert.ok(!body.text.includes("<b>&"));
    assert.ok([...plainText(body.text).match(/^Search: (.*)$/m)[1]].length <= 80);
    for (const button of buttons(body)) assert.ok(Buffer.byteLength(button.callback_data) <= 64);
  }
  const http = sentBody(await invoke({ text: "/formats HTTP Injector" }));
  assert.deepEqual(formatButtons(http).map(button => button.text.split(" · .")[1]).sort(), ["ehi", "ehil"]);
  const technical = sentBody(await invoke({ text: "/formats PBKDF2" }));
  assert.equal(formatButtons(technical).length, 0);
});

test("non-admin private uploads retain the three membership checks", async () => {
  const { calls } = await invoke({
    document: { file_name: "config.npvs", file_size: 100, file_id: "synthetic" }
  }, { userId: 12345 });
  assert.equal(calls.filter(call => call.url.endsWith("/getChatMember")).length, 3);
  assert.equal(calls.filter(call => call.url.startsWith("https://api.github.com/")).length, 1);
});

test("group behavior is preserved and channel uploads remain blocked", async () => {
  const document = { file_name: "config.tls", file_size: 100, file_id: "synthetic" };
  const group = await invoke({ document }, { chatType: "supergroup", userId: 12345 });
  assert.equal(group.calls.filter(call => call.url.endsWith("/getChatMember")).length, 0);
  assert.equal(group.calls.filter(call => call.url.startsWith("https://api.github.com/")).length, 1);
  const channel = await invoke({ document }, { chatType: "channel" });
  assert.equal(channel.calls.filter(call => call.url.startsWith("https://api.github.com/")).length, 0);
});
