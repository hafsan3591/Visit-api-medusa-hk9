from flask import Flask, request, jsonify
import asyncio, time, binascii, json
import aiohttp, requests
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import like_pb2, uid_generator_pb2, visit_count_pb2
from collections import OrderedDict

app = Flask(__name__)

VALID_API_KEYS = {"HK345"}
daily_limit = 200
used_count = 0


def load_tokens(region):
    try:
        if region == "IND":
            with open("token_ind.json") as f: return json.load(f)
        elif region in {"BR","US","SAC","NA"}:
            with open("token_br.json") as f: return json.load(f)
        else:
            with open("token_bd.json") as f: return json.load(f)
    except Exception as e:
        app.logger.error(f"token load err: {e}")
        return None


def encrypt_message(plaintext):
    key = b'Yg&tc%DEuh6%Zc^8'
    iv  = b'6oyZDr22E3ychjM%'
    return binascii.hexlify(
        AES.new(key, AES.MODE_CBC, iv).encrypt(pad(plaintext, AES.block_size))
    ).decode('utf-8')


def encrypt_like(uid, region):
    m = like_pb2.like(); m.uid = int(uid); m.region = region
    return encrypt_message(m.SerializeToString())


def encrypt_uid_proto(uid):
    m = uid_generator_pb2.uid_generator(); m.saturn_ = int(uid); m.garena = 1
    return encrypt_message(m.SerializeToString())


def headers(token):
    return {
        "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
        "Connection": "Keep-Alive",
        "Accept-Encoding": "gzip",
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/x-www-form-urlencoded",
        "Expect": "100-continue",
        "X-Unity-Version": "2018.4.11f1",
        "X-GA": "v1 1",
        "ReleaseVersion": "OB55"
    }


def post_sync(url, enc_hex, token):
    try:
        return requests.post(url, data=bytes.fromhex(enc_hex),
                             headers=headers(token), verify=False, timeout=15)
    except Exception as e:
        app.logger.error(f"post_sync err {url}: {e}")
        return None


# ========= URL ROUTERS =========
def base_url(region):
    if region == "IND": return "https://client.ind.freefiremobile.com"
    if region in {"BR","US","SAC","NA"}: return "https://client.us.freefiremobile.com"
    return "https://clientbp.ggpolarbear.com"

def show_url(region):    return base_url(region) + "/GetPlayerPersonalShow"
def like_url(region):    return base_url(region) + "/LikeProfile"

# 🎯 Friend request endpoints — multiple candidates (একটা কাজ করবে)
FRIEND_ENDPOINTS = [
    "/RequestAddingFriend",
    "/FriendRequest",
    "/AddFriend",
    "/SendFriendRequest",
    "/friend_request",
    "/RequestFriend",
]


def fetch_info(uid, region, token):
    r = post_sync(show_url(region), encrypt_uid_proto(uid), token)
    if r is None: return None
    try:
        info = visit_count_pb2.Info()
        info.ParseFromString(r.content)
        return info
    except Exception as e:
        app.logger.error(f"parse err: {e}")
        return None


# ========= CORE: try like with ALL tokens until it works =========
def try_like_until_success(uid, region, tokens, target_likes):
    encrypted = encrypt_like(uid, region)
    url = like_url(region)
    tried = []

    for i, td in enumerate(tokens):
        tk = td.get("token")
        if not tk: continue
        hint = f"...{tk[-8:]}"

        try:
            r = post_sync(url, encrypted, tk)
            if r is None:
                tried.append({"token": i+1, "hint": hint, "http": "err"})
                continue

            if r.status_code != 200:
                tried.append({"token": i+1, "hint": hint, "http": r.status_code})
                continue

            # 200 → server may have accepted. Verify.
            time.sleep(1.0)
            chk = fetch_info(uid, region, tk)
            if chk and chk.AccountInfo.Likes > target_likes:
                tried.append({"token": i+1, "hint": hint,
                              "http": 200, "likes": chk.AccountInfo.Likes})
                return {
                    "success": True,
                    "token_no": i+1,
                    "token_hint": hint,
                    "likes_after": chk.AccountInfo.Likes,
                    "gained": chk.AccountInfo.Likes - target_likes,
                    "tried": tried,
                }
            else:
                tried.append({"token": i+1, "hint": hint,
                              "http": 200, "note": "no increment"})
        except Exception as e:
            tried.append({"token": i+1, "hint": hint, "err": str(e)})

    return {
        "success": False,
        "token_no": None,
        "token_hint": None,
        "likes_after": target_likes,
        "gained": 0,
        "tried": tried,
    }


# ========= Friend request — try multiple endpoints =========
def try_friend_request(uid, region, token):
    encrypted = encrypt_like(uid, region)  # reuse like proto (uid + region)
    endpoint_tries = []

    for ep in FRIEND_ENDPOINTS:
        url = base_url(region) + ep
        r = post_sync(url, encrypted, token)
        if r is None:
            endpoint_tries.append({"ep": ep, "http": "err"})
            continue
        endpoint_tries.append({
            "ep": ep,
            "http": r.status_code,
            "len": len(r.content),
        })
        # 404 → endpoint doesn't exist → try next
        if r.status_code == 404:
            continue
        # 200/204/400 → endpoint exists (return whatever it returned)
        return {
            "success": r.status_code in (200, 204),
            "endpoint": ep,
            "http": r.status_code,
            "len": len(r.content),
            "tried": endpoint_tries,
        }

    return {"success": False, "endpoint": None, "http": 404, "tried": endpoint_tries}


@app.route('/visit', methods=['GET'])
def handle_visits():
    global used_count

    if request.args.get("key") not in VALID_API_KEYS:
        return app.response_class(
            response=json.dumps({"error":"Invalid API key","status":3}),
            status=401, mimetype='application/json')

    uid    = request.args.get("uid")
    region = request.args.get("region","").upper()
    if not uid or not region:
        return {"error":"uid and region required"}, 400

    try:
        tokens = load_tokens(region)
        if not tokens:
            raise Exception("No tokens")
        token0 = tokens[0]['token']

        # 1) BEFORE
        before = fetch_info(uid, region, token0)
        if before is None:
            raise Exception("Failed to fetch player info")
        likes_before = before.AccountInfo.Likes

        # 2) LIKE — try tokens sequentially until increment
        like_result = try_like_until_success(uid, region, tokens, likes_before)

        # 3) FRIEND — try multiple endpoints
        friend_result = try_friend_request(uid, region, token0)

        # 4) AFTER
        likes_after = like_result["likes_after"]
        likes_given = like_result["gained"]

        status = 1 if likes_given > 0 else 2
        if status == 1:
            used_count += 1
        remaining = max(daily_limit - used_count, 0)

        result = OrderedDict([
            ("PlayerNickname", before.AccountInfo.PlayerNickname),
            ("UID",            before.AccountInfo.UID),
            ("Region",         before.AccountInfo.PlayerRegion),
            ("Level",          before.AccountInfo.Levels),
            ("LikesBefore",    likes_before),
            ("LikesAfter",     likes_after),
            ("LikesGiven",     likes_given),
            ("LikeTokenUsed",  like_result["token_hint"] or "-"),
            ("LikeTokenNo",    like_result["token_no"] or "-"),
            ("LikeTried",      like_result["tried"]),
            ("FriendRequest",  "sent" if friend_result["success"] else "failed"),
            ("FriendEndpoint", friend_result.get("endpoint") or "-"),
            ("FriendHttp",     friend_result.get("http")),
            ("FriendTried",    friend_result.get("tried", [])),
            ("status",         status),
            ("daily_limit",    daily_limit),
            ("used",           used_count),
            ("remaining",      remaining),
        ])
        return app.response_class(
            response=json.dumps(result, separators=(',',':')),
            status=200, mimetype='application/json')

    except Exception as e:
        app.logger.error(f"visit err: {e}")
        return {"error": str(e)}, 500


@app.route('/like', methods=['GET'])
def like_legacy():
    return handle_visits()


@app.route('/remain', methods=['GET'])
def remain_info():
    return jsonify({
        "daily_limit": daily_limit,
        "remaining":   max(daily_limit - used_count, 0),
        "used":        used_count,
        "reset_info":  "4:00 AM IST"
    })


if __name__ == '__main__':
    app.run(debug=True, use_reloader=False, host='0.0.0.0', port=5000)
