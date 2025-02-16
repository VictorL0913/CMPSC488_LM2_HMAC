import hmac
import hashlib
import base64

def compute_hmac(message, secret_key):
    """Compute the HMAC of a message using a secret key.

    Args:
        message (str): The message to be hashed.
        secret_key (str): The secret key used for HMAC.

    Returns:
        str: The Base64 encoded HMAC of the message.
    """
    
    hash_algorithm = hashlib.sha256
    # Compute the HMAC using the hash function and the secret key
    hmac_object = hmac.new(secret_key.encode(), message.encode(), hash_algorithm)
    # Get the HMAC value
    hmac_digest = hmac_object.digest()
    # Encode the digest to Base64 or hexadecimal
    encoded_hmac = base64.b64encode(hmac_digest).decode()  # Base64 encoding
    return encoded_hmac

def appSend(message, secret_key):
    """Create a payload containing a message and HMAC.

    Args:
        message (str): message sent that will be hashed
        secret_key (str): secret key used for hashing

    Returns:
        dict: A dictionary containing the message and its HMAC.
    """
    hmac_value = compute_hmac(message, secret_key)
    payload = {
        'message': message,
        'hmac': hmac_value
    }
    return payload

def appRecv(payload, secret_key):
    """Receive a payload and verify HMAC.

    Args:
        payload (dict): The payload containing the message and HMAC.
        secret_key (str): The secret key used for HMAC.
    """
    # Get message and HMAC from payload
    message = payload['message']
    received_hmac = payload['hmac']
    # HMAC for the received message
    expected_hmac = compute_hmac(message, secret_key)
    # Verify HMAC
    if hmac.compare_digest(received_hmac, expected_hmac):
        print("HMAC verified. Message:", message)
    else:
        print("HMAC verification failed. Message may be tampered.")

# Example usage
message = "Hello World"
secret_key = "mySecretKey"

# sending payload
payload = appSend(message, secret_key)
print("Payload:", payload)

# Receiving payload
appRecv(payload, secret_key)

