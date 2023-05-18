import requests
from django.conf import settings


def send_otp(mobile, otp):
    """
    Send message.
    """
    url = f"https://2factor.in/API/V1/{settings.SMS_API_KEY}/SMS/{mobile}/{otp}/Your OTP is"
    payload = ""
    headers = {'content-type': 'application/x-www-form-urlencoded'}
    response = requests.get(url, data=payload, headers=headers)
    return bool(response.ok)


#for test

from django.conf import settings
from datetime import datetime, timedelta
import jwt


def generate_access_token(user):
	payload = {
		'user_id': user.id,
		'exp': datetime.utcnow() + timedelta(days=1, minutes=0),
		'iat': datetime.utcnow(),
	}

	access_token = jwt.encode(payload, settings.SECRET_KEY, algorithm='HS256')
	return access_token