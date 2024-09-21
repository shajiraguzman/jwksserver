# Shajira Guzman

from datetime import datetime, timedelta
from flask import Flask, jsonify, request
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
import jwt
import base64



# generate flask app
app = Flask(__name__)

# store keys with their exp time
keys = {}

# generate RSA key pairs
def generate_rsa_key():

    #print("Starting Key generation")
    expired = request.args.get('expired')               # get expiration (true or false) from request

    privateKey = rsa.generate_private_key(              # generate private key and set variables
        key_size = 2048,
        public_exponent = 65537,
        backend = default_backend()
    )
    publicKey = privateKey.public_key()                 # get public key
    kid = str(len(keys) + 1)                            # create key ID

    if expired:
        expirationTime = datetime.utcnow() - timedelta(days=1)  # set exp a day behind
    else:
        expirationTime = datetime.utcnow() + timedelta(days=5)  # set exp to expire in 5 days
    keys[kid] = (publicKey, privateKey, expirationTime)

    return kid


# JWKS endpoint
@app.route('/.well-known/jwks.json', methods=['GET'])
def jwks():

    #print("start endpoint")
    jwksKeys = []
    currenTime = datetime.utcnow()

    # iterate over stored keys and store non expired keys
    for kid, (publicKey, privateKey, expirationTime) in keys.items():
        if currenTime < expirationTime:
            n = publicKey.public_numbers().n.to_bytes((publicKey.public_numbers().n.bit_length() + 7) // 8, byteorder='big')  # get modulus from key to convert to base64URL later
            e = publicKey.public_numbers().e.to_bytes((publicKey.public_numbers().e.bit_length() + 7) // 8, byteorder='big')  # get exponent from key to convert to base64URL later
            
            # set kid, key type, algorithm, use, modulus and exponent
            jwksKeys.append({
                "kid": kid,
                "kty": "RSA",
                "alg": "RS256",
                "use": "sig", 
                "n": base64.urlsafe_b64encode(n).rstrip(b'=').decode('utf-8'), 
                "e": base64.urlsafe_b64encode(e).rstrip(b'=').decode('utf-8')
            }) 
    
    print(keys)
    return jsonify(keys=jwksKeys)


# authentication endpoint
@app.route('/auth', methods=['POST'])
def authenticate():

    #print("start auth")
    expired = request.args.get('expired')

    # set exp time to a day behind or 5 hours later
    if expired:
        print("Expired")
        expirationTime = datetime.utcnow() - timedelta(days=1)
    else: 
        print("Not expired")
        expirationTime = datetime.utcnow() + timedelta(hours=5)
    
    print(expirationTime)
    kid = generate_rsa_key()
    privateKey = keys[kid][1]
    payload = {'username': 'tempUser', 'exp': int(expirationTime.timestamp())}
    token = jwt.encode(payload, privateKey, algorithm='RS256', headers={'kid': kid})

    return jsonify(token=token)



if __name__ == '__main__':
    app.run(port=8080)
