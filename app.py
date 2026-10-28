from flask import Flask, request, jsonify
import asyncio
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import binascii
import aiohttp
import requests
import json
import like_pb2
import uid_generator_pb2
import visit_count_pb2
from google.protobuf.message import DecodeError
from collections import OrderedDict

app = Flask(__name__)

VALID_API_KEYS = {"HK345"}
daily_limit = 200
used_count = 0


def load_tokens(region):
    try:
        if region == "IND":
            with open("token_ind.json") as f: return json.load(f)
        elif region in {"BR", "US", "SAC", "NA"}:
            with open("token_br.json") as f: return json.load(f)
        else:
            with open("token_bd.json") as f: return json.load(f)
    except Exception as e:
        app.logger.error(f"token load err: {e}")
        return None


def encrypt_message(plaintext):
    key = b'Yg&tc%DEuh6%Zc^8'
    iv  = b'6oyZDr22E3ychjM%'
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return binascii.hexlify(cipher.encrypt(pad(plaintext, AES.block_size))).decode('utf-8')


def encrypt_like_message(uid, region):
    msg = like_pb2.like()
    msg.uid = int(uid)
    msg.region = region
    return encrypt_message(msg.SerializeToString())


def encrypt_uid_proto(uid):
    msg = uid_generator_pb2.uid_generator()
    msg.saturn_ = int(uid)
    msg.garena = 1
    return encrypt_message(msg.SerializeToString())


def _headers(token):
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


async def post_async(url, encrypted_hex, token):
    try:
        edata = bytes.fromhex(encrypted_hex)
        async with aiohttp.ClientSession() as s:
            async with s.post(url, data=edata, headers=_headers(token),
                              timeout=aiohttp.ClientTimeout(total=20)) as r:
                body = await r.text()
                return {"success": r.status == 200, "status": r.status,
                        "len": len(body)}
    except Exception as e:
        return {"success": False, "error": str(e)}


def post_sync(url, encrypted_hex, token):
    edata = bytes.fromhex(encrypted_hex)
    return requests.post(url, data=edata, headers=_headers(token),
                         verify=False, timeout=15)


def get_show_url(region):
    if region == "IND": return "https://client.ind.freefiremobile.com/GetPlayerPersonalShow"
    if region in {"BR","US","SAC","NA"}: return "https://client.us.freefiremobile.com/GetPlayerPersonalShow"
    return "https://clientbp.ggpolarbear.com/GetPlayerPersonalShow"

def get_like_url(region):
    if region == "IND": return "https://client.ind.freefiremobile.com/LikeProfile"
    if region in {"BR","US","SAC","NA"}: return "https://client.us.freefiremobile.com/LikeProfile"
    return "https://clientbp.ggpolarbear.com/LikeProfile"

def get_friend_url(region):
    if region == "IND": return "https://client.ind.freefiremobile.com/FriendRequest"
    if region in {"BR","US","SAC","NA"}: return "https://client.us.freefiremobile.com/FriendRequest"
    return "https://clientbp.ggpolarbear.com/FriendRequest"


def fetch_player_info(uid, region, token):
    try:
        encrypted = encrypt_uid_proto(uid)
        r = post_sync(get_show_url(region), encrypted, token)
        info = visit_count_pb2.Info()
        info.ParseFromString(r.content)
        return info
    except Exception as e:
        app.logger.error(f"info err: {e}")
        return None


@app.route('/visit', methods=['GET'])
def handle_visits():
    global used_count

    api_key = request.args.get("key")
    if api_key not in VALID_API_KEYS:
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
            raise Exception("No tokens available")
        token = tokens[0]['token']

        # 1) BEFORE info
        before = fetch_player_info(uid, region, token)
        if before is None:
            raise Exception("Failed to fetch player info")
        likes_before = before.AccountInfo.Likes

        # 2) Send 1 like + 1 friend request concurrently
        encrypted_like = encrypt_like_message(uid, region)

        async def do_both():
            like_res   = await post_async(get_like_url(region),   encrypted_like, token)
            friend_res = await post_async(get_friend_url(region), encrypted_like, token)
            return like_res, friend_res

        like_res, friend_res = asyncio.run(do_both())

        # 3) AFTER info
        after = fetch_player_info(uid, region, token)
        likes_after = after.AccountInfo.Likes if after else likes_before
        likes_given = likes_after - likes_before

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
            ("FriendRequest",  "sent" if friend_res.get("success") else "failed"),
            ("FriendStatus",   friend_res.get("status", friend_res.get("error","-"))),
            ("LikeStatus",     like_res.get("status", like_res.get("error","-"))),
            ("status",         status),
            ("daily_limit",    daily_limit),
            ("used",           used_count),
            ("remaining",      remaining)
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