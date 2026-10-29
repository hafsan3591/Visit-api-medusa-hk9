from flask import Flask, request, jsonify
import asyncio
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import binascii
import aiohttp
import requests
import json
import os
import like_pb2
import uid_generator_pb2
from collections import OrderedDict

app = Flask(__name__)

# ================= CONFIG =================
VALID_API_KEYS = {"HK345"}
daily_limit = 200
used_count = 0
BOT_TOKEN = os.environ.get("BOT_TOKEN", "")   # Vercel Env Var দাও

# ================= HELPERS =================
def load_tokens(region):
    try:
        if region == "IND":
            fname = "token_ind.json"
        elif region in {"BR", "US", "SAC", "NA"}:
            fname = "token_br.json"
        else:
            fname = "token_bd.json"
        with open(fname, "r") as f:
            return json.load(f)
    except Exception as e:
        app.logger.error(f"load_tokens {region}: {e}")
        return None


def encrypt_message(plaintext):
    try:
        key = b'Yg&tc%DEuh6%Zc^8'
        iv = b'6oyZDr22E3ychjM%'
        cipher = AES.new(key, AES.MODE_CBC, iv)
        padded = pad(plaintext, AES.block_size)
        return binascii.hexlify(cipher.encrypt(padded)).decode('utf-8')
    except Exception as e:
        app.logger.error(f"encrypt_message: {e}")
        return None


def create_protobuf_message(user_id, region):
    try:
        m = like_pb2.like()
        m.uid = int(user_id)
        m.region = region
        return m.SerializeToString()
    except Exception as e:
        app.logger.error(f"create_protobuf_message: {e}")
        return None


def create_protobuf(uid):
    try:
        m = uid_generator_pb2.uid_generator()
        m.saturn_ = int(uid)
        m.garena = 1
        return m.SerializeToString()
    except Exception as e:
        app.logger.error(f"create_protobuf: {e}")
        return None


def enc(uid):
    pb = create_protobuf(uid)
    return encrypt_message(pb) if pb else None


# ================= URLs =================
BD_PERSONAL_SHOW_URL = "https://clientbp.ggpolarbear.com/GetPlayerPersonalShow"
BD_VISIT_URL         = "https://clientbp.ggpolarbear.com/VisitProfile"


def get_visit_url(region):
    if region == "IND":
        return "https://client.ind.freefiremobile.com/VisitProfile"
    if region in {"BR", "US", "SAC", "NA"}:
        return "https://client.us.freefiremobile.com/VisitProfile"
    return BD_VISIT_URL


def get_personal_show_url(region):
    if region == "IND":
        return "https://client.ind.freefiremobile.com/GetPlayerPersonalShow"
    if region in {"BR", "US", "SAC", "NA"}:
        return "https://client.us.freefiremobile.com/GetPlayerPersonalShow"
    return BD_PERSONAL_SHOW_URL


def build_headers(token):
    return {
        "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
        "Connection": "Keep-Alive",
        "Accept-Encoding": "gzip",
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/x-www-form-urlencoded",
        "Expect": "100-continue",
        "X-Unity-Version": "2018.4.11f1",
        "X-GA": "v1 1",
        "ReleaseVersion": "OB55",
    }


# ================= ASYNC VISIT =================
async def send_request(encrypted_uid, token, url):
    try:
        edata = bytes.fromhex(encrypted_uid)
        headers = build_headers(token)
        async with aiohttp.ClientSession() as session:
            async with session.post(url, data=edata, headers=headers) as resp:
                return await resp.text()
    except Exception as e:
        app.logger.error(f"send_request: {e}")
        return None


async def send_visits_with_all_tokens(uid, region, url, tokens):
    try:
        pb = create_protobuf_message(uid, region)
        if pb is None:
            return []
        encrypted_uid = encrypt_message(pb)
        if encrypted_uid is None:
            return []
        tasks = []
        for t in tokens:
            tok = t.get("token")
            if tok:
                tasks.append(send_request(encrypted_uid, tok, url))
        if not tasks:
            return []
        return await asyncio.gather(*tasks, return_exceptions=True)
    except Exception as e:
        app.logger.error(f"send_visits_with_all_tokens: {e}")
        return []


# ================= RAW PROTOBUF DECODER =================
def _read_varint(data, i):
    result = 0
    shift = 0
    while i < len(data):
        b = data[i]
        result |= (b & 0x7F) << shift
        i += 1
        if not (b & 0x80):
            break
        shift += 7
    return result, i


def parse_protobuf(data, depth=0, max_depth=15, strict=False):
    """Schema-free protobuf parser. Returns nested dict {fN: value}"""
    if depth > max_depth:
        return None if strict else {}
    result = {}
    i = 0
    data = bytes(data)
    while i < len(data):
        try:
            tag, i = _read_varint(data, i)
            field_num = tag >> 3
            wire_type = tag & 0x7
            if field_num == 0 or field_num > 536870911:
                if strict: return None
                break
            key = f"f{field_num}"

            if wire_type == 0:
                value, i = _read_varint(data, i)

            elif wire_type == 1:
                if i + 8 > len(data):
                    if strict: return None
                    break
                value = int.from_bytes(data[i:i+8], 'little')
                i += 8

            elif wire_type == 2:
                length, i = _read_varint(data, i)
                if i + length > len(data):
                    if strict: return None
                    break
                raw = data[i:i+length]
                i += length

                nested = None
                if length >= 2:
                    try:
                        nested = parse_protobuf(raw, depth+1, max_depth, strict=True)
                    except Exception:
                        nested = None

                if nested is not None and len(nested) > 0:
                    value = nested
                else:
                    try:
                        s = raw.decode('utf-8')
                        if all(c.isprintable() or c in '\n\r\t' for c in s):
                            value = s
                        else:
                            value = raw.hex()
                    except Exception:
                        value = raw.hex()

            elif wire_type == 5:
                if i + 4 > len(data):
                    if strict: return None
                    break
                value = int.from_bytes(data[i:i+4], 'little')
                i += 4

            else:
                if strict: return None
                break

            if key in result:
                if not isinstance(result[key], list):
                    result[key] = [result[key]]
                result[key].append(value)
            else:
                result[key] = value
        except Exception:
            if strict: return None
            break

    if strict and i != len(data):
        return None
    return result


# ================= FETCH RAW =================
def fetch_raw_info(uid, region):
    tokens = load_tokens(region)
    if not tokens:
        raise Exception(f"No tokens for region {region}")
    encrypted_uid = enc(uid)
    if encrypted_uid is None:
        raise Exception("Encryption failed")
    url = get_personal_show_url(region)
    edata = bytes.fromhex(encrypted_uid)
    headers = build_headers(tokens[0]['token'])
    resp = requests.post(url, data=edata, headers=headers, verify=False, timeout=15)
    if resp.status_code != 200:
        raise Exception(f"HTTP {resp.status_code}")
    return resp.content


def build_info_dict(uid, region):
    raw = fetch_raw_info(uid, region)
    parsed = parse_protobuf(raw)
    account = parsed.get('f1', {}) if isinstance(parsed.get('f1'), dict) else {}

    known = OrderedDict([
        ("UID",            account.get('f1') or uid),   # fallback to search uid
        ("PlayerNickname", account.get('f3')),
        ("PlayerRegion",   account.get('f5')),
        ("Levels",         account.get('f6')),
        ("Likes",          account.get('f21')),
    ])
    return {"known": known, "raw": parsed}


# ============ BOT FORMAT: Name / UID / Likes / Status ============
def format_info_text(info, search_uid=None):
    """Bot শুধু Name, UID, Likes, Status দেখাবে — UID কখনোই ফাঁকা থাকবে না।"""
    k = info["known"]
    nickname = k.get('PlayerNickname')
    uid      = k.get('UID') or search_uid        # fallback
    likes    = k.get('Likes')

    is_active = bool(nickname) and bool(uid)
    status    = "✅ Active & Connected" if is_active else "❌ Inactive / Not Found"

    lines = [
        "┌ 𝐀𝐂𝐂𝐎𝐔𝐍𝐓 𝐈𝐍𝐅𝐎",
        f"├─ 👤 Name   : {nickname if nickname else 'N/A'}",
        f"├─ 🆔 UID    : {uid if uid else 'N/A'}",
        f"├─ ❤️ Likes  : {likes if likes is not None else 0}",
        f"└─ 📡 Status : {status}",
    ]
    return "\n".join(lines)


def format_inactive(uid, reason=""):
    """ফেচ ফেইল করলেও UID দেখাবে।"""
    txt = (
        "┌ 𝐀𝐂𝐂𝐎𝐔𝐍𝐓 𝐈𝐍𝐅𝐎\n"
        f"├─ 👤 Name   : N/A\n"
        f"├─ 🆔 UID    : {uid if uid else 'N/A'}\n"
        f"├─ ❤️ Likes  : 0\n"
        f"└─ 📡 Status : ❌ Inactive / Not Connected"
    )
    if reason:
        txt += f"\n\n⚠️ {reason}"
    return txt


# ================= ROUTES =================
@app.route('/visit', methods=['GET'])
def handle_visits():
    global used_count
    if request.args.get("key") not in VALID_API_KEYS:
        return app.response_class(
            response=json.dumps(OrderedDict([("error","Invalid API key"),("status",3)]), separators=(',',':')),
            status=401, mimetype='application/json')

    uid    = request.args.get("uid")
    region = request.args.get("region", "").upper()
    if not uid or not region:
        return {"error": "UID and region required"}, 400

    try:
        tokens = load_tokens(region)
        if not tokens:
            raise Exception("Failed to load tokens")

        encrypted_uid = enc(uid)
        if not encrypted_uid:
            raise Exception("Encryption failed")

        edata = bytes.fromhex(encrypted_uid)
        headers = build_headers(tokens[0]['token'])
        r = requests.post(get_personal_show_url(region),
                          data=edata, headers=headers, verify=False, timeout=15)
        parsed = parse_protobuf(r.content)
        acc = parsed.get('f1', {}) if isinstance(parsed.get('f1'), dict) else {}

        results = asyncio.run(send_visits_with_all_tokens(
            uid, region, get_visit_url(region), tokens))
        ok   = sum(1 for x in results if x is not None and not isinstance(x, Exception))
        fail = len(results) - ok
        status = 1 if ok > 0 else 2
        if status == 1:
            used_count += 1

        out = OrderedDict([
            ("TotalTokens",    len(tokens)),
            ("VisitsSent",     ok),
            ("VisitsFailed",   fail),
            ("PlayerNickname", acc.get('f3', 'N/A')),
            ("Level",          acc.get('f6', 0)),
            ("Region",         acc.get('f5', region)),
            ("UID",            acc.get('f1', uid)),
            ("status",         status),
            ("daily_limit",    daily_limit),
            ("used",           used_count),
            ("remaining",      max(daily_limit - used_count, 0)),
        ])
        return app.response_class(
            response=json.dumps(out, separators=(',',':'), ensure_ascii=False),
            status=200, mimetype='application/json')
    except Exception as e:
        app.logger.error(f"visit error: {e}")
        return {"error": str(e)}, 500


@app.route('/like', methods=['GET'])
def handle_like_legacy():
    return handle_visits()


@app.route('/info', methods=['GET'])
def handle_info():
    if request.args.get("key") not in VALID_API_KEYS:
        return {"error": "Invalid API key", "status": 3}, 401
    uid    = request.args.get("uid")
    region = request.args.get("region", "").upper()
    if not uid or not region:
        return {"error": "UID and region required"}, 400
    try:
        data = build_info_dict(uid, region)
        return app.response_class(
            response=json.dumps(data, separators=(',',':'), ensure_ascii=False, default=str),
            status=200, mimetype='application/json')
    except Exception as e:
        app.logger.error(f"info error: {e}")
        return {"error": str(e)}, 500


@app.route('/decode', methods=['GET'])
def handle_decode():
    if request.args.get("key") not in VALID_API_KEYS:
        return {"error": "Invalid API key", "status": 3}, 401
    uid    = request.args.get("uid")
    region = request.args.get("region", "").upper()
    if not uid or not region:
        return {"error": "UID and region required"}, 400
    try:
        raw    = fetch_raw_info(uid, region)
        parsed = parse_protobuf(raw)
        return app.response_class(
            response=json.dumps(
                {"parsed": parsed, "raw_hex": raw.hex(), "length": len(raw)},
                separators=(',',':'), ensure_ascii=False, default=str),
            status=200, mimetype='application/json')
    except Exception as e:
        app.logger.error(f"decode error: {e}")
        return {"error": str(e)}, 500


@app.route('/remain', methods=['GET'])
def remain_info():
    return jsonify({
        "daily_limit": daily_limit,
        "remaining":   max(daily_limit - used_count, 0),
        "used":        used_count,
        "reset_info":  "4:00 AM IST",
    })


# ================= TELEGRAM BOT (webhook) =================
def tg_send(chat_id, text):
    if not BOT_TOKEN:
        return
    try:
        requests.post(
            f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage",
            json={"chat_id": chat_id, "text": text},
            timeout=10)
    except Exception as e:
        app.logger.error(f"tg_send: {e}")


@app.route('/webhook/<token>', methods=['POST'])
def tg_webhook(token):
    if not BOT_TOKEN or token != BOT_TOKEN:
        return "forbidden", 403
    update = request.get_json(silent=True)
    if not update or 'message' not in update:
        return "ok", 200
    msg     = update['message']
    chat_id = msg['chat']['id']
    text    = (msg.get('text') or '').strip()

    if text.startswith('/start'):
        tg_send(chat_id,
            "🎮 Free Fire Bot\n\n"
            "/info <UID> <REGION>    — Name, UID, Likes, Status\n"
            "/visit <UID> <REGION>   — Visit + info\n\n"
            "REGION: BD, IND, BR, US, SAC, NA")
        return "ok", 200

    parts = text.split()
    if len(parts) < 3:
        tg_send(chat_id, "Usage: /cmd <UID> <REGION>")
        return "ok", 200

    cmd, uid, region = parts[0].lower(), parts[1], parts[2].upper()

    try:
        if cmd == '/info':
            tg_send(chat_id, "⏳ Fetching...")
            try:
                tg_send(chat_id, format_info_text(build_info_dict(uid, region), search_uid=uid))
            except Exception as e:
                tg_send(chat_id, format_inactive(uid, str(e)))

        elif cmd == '/decode':
            raw    = fetch_raw_info(uid, region)
            parsed = parse_protobuf(raw)
            txt = "🔍 Raw:\n" + json.dumps(parsed, indent=2, ensure_ascii=False, default=str)[:3800]
            tg_send(chat_id, txt)

        elif cmd == '/visit':
            tokens = load_tokens(region)
            if not tokens:
                tg_send(chat_id, "❌ No tokens")
                return "ok", 200
            tg_send(chat_id, f"⏳ {len(tokens)} tokens দিয়ে পাঠাচ্ছি...")
            results = asyncio.run(send_visits_with_all_tokens(
                uid, region, get_visit_url(region), tokens))
            ok = sum(1 for x in results if x is not None and not isinstance(x, Exception))
            try:
                tg_send(chat_id, format_info_text(build_info_dict(uid, region), search_uid=uid))
            except Exception as e:
                tg_send(chat_id, format_inactive(uid, str(e)))
            tg_send(chat_id, f"✅ {ok}/{len(tokens)} visits sent")
        else:
            tg_send(chat_id, "Unknown command। /start দাও")
    except Exception as e:
        tg_send(chat_id, f"❌ {e}")

    return "ok", 200


@app.route('/set_webhook', methods=['GET'])
def set_webhook():
    base = request.args.get("base")
    if not base or not BOT_TOKEN:
        return {"error": "?base=URL এবং BOT_TOKEN env দরকার"}, 400
    url = f"{base.rstrip('/')}/webhook/{BOT_TOKEN}"
    r = requests.get(f"https://api.telegram.org/bot{BOT_TOKEN}/setWebhook?url={url}")
    return r.json()


if __name__ == '__main__':
    app.run(debug=True, use_reloader=False, host='0.0.0.0', port=5000)nn.dumps({
                "parsed": parsed,
                "raw_hex": raw.hex(),
                "length": len(raw),
            }, separators=(',',':'), ensure_ascii=False, default=str),
            status=200, mimetype='application/json')
    except Exception as e:
        app.logger.error(f"/rawdata error: {e}")
        return {"error": str(e)}, 500


# ✅ /visit — visit পাঠায়
@app.route('/visit', methods=['GET'])
def handle_visits():
    global used_count
    if request.args.get("key") not in VALID_API_KEYS:
        return {"error": "Invalid API key", "status": 3}, 401

    region = request.args.get("region", "").upper()
    uid    = request.args.get("uid", "").strip()

    if not region or not uid:
        return {"error": "region and uid required"}, 400
    if not uid.isdigit():
        return {"error": "uid must be numeric"}, 400
    if region not in VALID_REGIONS:
        return {"error": "invalid region", "valid": list(VALID_REGIONS)}, 400

    try:
        tokens = load_tokens(region)
        if not tokens:
            raise Exception(f"No tokens for region {region}")

        raw    = fetch_raw_info(uid, region)
        player = extract_player(raw, uid)

        results = asyncio.run(send_visits_with_all_tokens(
            uid, region, get_visit_url(region), tokens))

        ok = sum(1 for x in results if x is not None and not isinstance(x, Exception))
        status = 1 if ok > 0 else 2
        if status == 1:
            used_count += 1

        out = OrderedDict([
            ("TotalTokens",    len(tokens)),
            ("VisitsSent",     ok),
            ("VisitsFailed",   len(results) - ok),
            ("PlayerNickname", player["PlayerNickname"]),
            ("Level",          player["Levels"]),
            ("Region",         player["PlayerRegion"] or region),
            ("UID",            player["UID"]),
            ("status",         status),
            ("daily_limit",    daily_limit),
            ("used",           used_count),
            ("remaining",      max(daily_limit - used_count, 0)),
        ])
        return app.response_class(
            response=json.dumps(out, separators=(',',':'), ensure_ascii=False),
            status=200, mimetype='application/json')
    except Exception as e:
        app.logger.error(f"/visit error: {e}")
        return {"error": str(e)}, 500


@app.route('/like', methods=['GET'])
def handle_like_legacy():
    return handle_visits()


@app.route('/remain', methods=['GET'])
def remain_info():
    return jsonify({
        "daily_limit": daily_limit,
        "remaining":   max(daily_limit - used_count, 0),
        "used":        used_count,
        "reset_info":  "4:00 AM IST",
    })


if __name__ == '__main__':
    app.run(debug=True, use_reloader=False, host='0.0.0.0', port=5000)
