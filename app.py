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

# ✅ Valid API keys
VALID_API_KEYS = {
    "HK345"
}

daily_limit = 200
used_count = 0


def load_tokens(region):
    try:
        if region == "IND":
            with open("token_ind.json", "r") as f:
                tokens = json.load(f)
        elif region in {"BR", "US", "SAC", "NA"}:
            with open("token_br.json", "r") as f:
                tokens = json.load(f)
        else:  # BD / default
            with open("token_bd.json", "r") as f:
                tokens = json.load(f)
        return tokens
    except Exception as e:
        app.logger.error(f"Error loading tokens for region {region}: {e}")
        return None


def encrypt_message(plaintext):
    try:
        key = b'Yg&tc%DEuh6%Zc^8'
        iv = b'6oyZDr22E3ychjM%'
        cipher = AES.new(key, AES.MODE_CBC, iv)
        padded_message = pad(plaintext, AES.block_size)
        encrypted_message = cipher.encrypt(padded_message)
        return binascii.hexlify(encrypted_message).decode('utf-8')
    except Exception as e:
        app.logger.error(f"Error encrypting message: {e}")
        return None


def create_protobuf_message(user_id, region):
    try:
        message = like_pb2.like()
        message.uid = int(user_id)
        message.region = region
        return message.SerializeToString()
    except Exception as e:
        app.logger.error(f"Error creating protobuf message: {e}")
        return None


async def send_request(encrypted_uid, token, url):
    try:
        edata = bytes.fromhex(encrypted_uid)
        headers = {
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
        async with aiohttp.ClientSession() as session:
            async with session.post(url, data=edata, headers=headers) as response:
                return await response.text()
    except Exception as e:
        app.logger.error(f"Exception in send_request: {e}")
        return None


async def send_visits_with_all_tokens(uid, region, url, tokens):
    """
    ✅ প্রতিটা token থেকে একটা visit request পাঠাবে — সবগুলো একসাথে (concurrent)।
    """
    try:
        protobuf_message = create_protobuf_message(uid, region)
        if protobuf_message is None:
            return []
        encrypted_uid = encrypt_message(protobuf_message)
        if encrypted_uid is None:
            return []

        tasks = []
        for token_data in tokens:
            token = token_data.get("token")
            if not token:
                continue
            tasks.append(send_request(encrypted_uid, token, url))

        if not tasks:
            return []

        results = await asyncio.gather(*tasks, return_exceptions=True)
        return results
    except Exception as e:
        app.logger.error(f"Exception in send_visits_with_all_tokens: {e}")
        return []


def create_protobuf(uid):
    try:
        message = uid_generator_pb2.uid_generator()
        message.saturn_ = int(uid)
        message.garena = 1
        return message.SerializeToString()
    except Exception as e:
        app.logger.error(f"Error creating uid protobuf: {e}")
        return None


def enc(uid):
    protobuf_data = create_protobuf(uid)
    if protobuf_data is None:
        return None
    return encrypt_message(protobuf_data)


# ✅ BD SERVER URLs
BD_PERSONAL_SHOW_URL = "https://clientbp.ggpolarbear.com/GetPlayerPersonalShow"
BD_VISIT_URL         = "https://clientbp.ggpolarbear.com/VisitProfile"


def get_visit_url(region):
    if region == "IND":
        return "https://client.ind.freefiremobile.com/VisitProfile"
    elif region in {"BR", "US", "SAC", "NA"}:
        return "https://client.us.freefiremobile.com/VisitProfile"
    else:  # BD
        return BD_VISIT_URL


def get_personal_show_url(region):
    if region == "IND":
        return "https://client.ind.freefiremobile.com/GetPlayerPersonalShow"
    elif region in {"BR", "US", "SAC", "NA"}:
        return "https://client.us.freefiremobile.com/GetPlayerPersonalShow"
    else:  # BD
        return BD_PERSONAL_SHOW_URL


def make_request(encrypt, region, token):
    try:
        url = get_personal_show_url(region)
        edata = bytes.fromhex(encrypt)
        headers = {
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
        response = requests.post(url, data=edata, headers=headers, verify=False, timeout=15)
        binary = response.content
        decoded = visit_count_pb2.Info()
        decoded.ParseFromString(binary)
        return decoded
    except DecodeError as e:
        app.logger.error(f"DecodeError: {e}")
        return None
    except Exception as e:
        app.logger.error(f"Error in make_request: {e}")
        return None


@app.route('/visit', methods=['GET'])
def handle_visits():
    global used_count

    api_key = request.args.get("key")
    if api_key not in VALID_API_KEYS:
        result = OrderedDict([
            ("error", "Invalid or missing API key"),
            ("status", 3)
        ])
        return app.response_class(
            response=json.dumps(result, separators=(',', ':')),
            status=401,
            mimetype='application/json'
        )

    uid = request.args.get("uid")
    region = request.args.get("region", "").upper()
    if not uid or not region:
        return {"error": "UID and region are required"}, 400

    try:
        def process_request():
            global used_count

            tokens = load_tokens(region)
            if not tokens:
                raise Exception("Failed to load tokens.")

            # 🔐 Encrypt target UID
            encrypted_uid = enc(uid)
            if encrypted_uid is None:
                raise Exception("Encryption of UID failed.")

            # 📊 Get player info (একবার latest token দিয়ে)
            first_token = tokens[0]['token']
            player_info = make_request(encrypted_uid, region, first_token)
            if player_info is None:
                raise Exception("Failed to get player info.")

            # 🚀 Send visits from ALL tokens (concurrent)
            visit_url = get_visit_url(region)
            results = asyncio.run(
                send_visits_with_all_tokens(uid, region, visit_url, tokens)
            )

            success_count = 0
            failed_count  = 0
            for r in results:
                if r is None or isinstance(r, Exception):
                    failed_count += 1
                else:
                    success_count += 1

            status = 1 if success_count > 0 else 2

            if status == 1:
                used_count += 1

            remaining = max(daily_limit - used_count, 0)

            result = OrderedDict([
                ("TotalTokens",    len(tokens)),
                ("VisitsSent",     success_count),
                ("VisitsFailed",   failed_count),
                ("PlayerNickname", player_info.AccountInfo.PlayerNickname),
                ("Level",          player_info.AccountInfo.Levels),
                ("Region",         player_info.AccountInfo.PlayerRegion),
                ("UID",            player_info.AccountInfo.UID),
                ("status",         status),
                ("daily_limit",    daily_limit),
                ("used",           used_count),
                ("remaining",      remaining)
            ])

            return app.response_class(
                response=json.dumps(result, separators=(',', ':')),
                status=200,
                mimetype='application/json'
            )

        return process_request()

    except Exception as e:
        app.logger.error(f"Error: {e}")
        return {"error": str(e)}, 500


# 🔁 Backward compatibility – পুরানো /like এখন visit পাঠাবে
@app.route('/like', methods=['GET'])
def handle_like_legacy():
    return handle_visits()


@app.route('/remain', methods=['GET'])
def remain_info():
    global used_count
    remaining = max(daily_limit - used_count, 0)
    data = {
        "daily_limit": daily_limit,
        "remaining":   remaining,
        "used":        used_count,
        "reset_info":  "4:00 AM IST"
    }
    return jsonify(data)


if __name__ == '__main__':
    app.run(debug=True, use_reloader=False, host='0.0.0.0', port=5000)