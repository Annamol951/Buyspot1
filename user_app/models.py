from django.db import models

# Create your models here.

from django.conf import settings
from django.contrib.auth.models import (
    AbstractBaseUser,
    BaseUserManager,
    Group,
    PermissionsMixin,
)
from django.core.validators import RegexValidator, validate_email


phone_regex = RegexValidator(
    regex=r"^\d{10}", message="Phone number must be 10 digits only."
)


class UserManager(BaseUserManager):
    """
    User Manager.
    To create superuser.
    """

    def create_user(self, phone_number, password=None):
        if not phone_number:
            raise ValueError("Users must have a phone_number")
        user = self.model(phone_number=phone_number)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, phone_number, password):
        user = self.create_user(
            phone_number=phone_number, password=password
        )
        user.is_active = True
        user.is_staff = True
        user.is_superuser = True
        user.save(using=self._db)
        return user


class UserModel(AbstractBaseUser, PermissionsMixin):
    """
    Custom User model.
    """

    phone_number = models.CharField(
        unique=True, max_length=10, null=False, blank=False, validators=[phone_regex]
    )
    email = models.EmailField(
        max_length=50,
        blank=True,
        null=True,
        validators=[validate_email],
    )

    first_name = models.CharField(max_length=50, null=False, blank=False)
    last_name = models.CharField(max_length=50, null=False, blank=False)
    email = models.EmailField(max_length=50, null=True, blank=True)
    address = models.TextField(max_length=255, null=False, blank=False)
    dob = models.DateField(null=False)
    pincode = models.IntegerField(default=0, null=False)

    otp = models.IntegerField() #IntegerField,max_length=6
    otp_expiry = models.DateTimeField(blank=True, null=True)
    max_otp_try = models.CharField(max_length=2, default=settings.MAX_OTP_TRY)
    otp_max_out = models.DateTimeField(blank=True, null=True)

    is_active = models.BooleanField(default=False)
    is_staff = models.BooleanField(default=False)
    user_registered_at = models.DateTimeField(auto_now_add=True)

    USERNAME_FIELD = "phone_number"

    objects = UserManager()

    def __str__(self):
        return self.phone_number


class UserProfile(models.Model):
    """
    User profile model.

    Every user should have only one profile.
    """

    user = models.OneToOneField(
        UserModel,
        related_name="profile",
        on_delete=models.CASCADE,
        primary_key=True,
    )
    

#delivery address

class DeliveryAddress(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    name = models.CharField(max_length=255)
    address_line_1 = models.CharField(max_length=255)
    address_line_2 = models.CharField(max_length=255, blank=True)
    city = models.CharField(max_length=255)
    state = models.CharField(max_length=255)
    district = models.CharField(max_length=255)
    mobile = models.CharField(max_length=10)
    zipcode = models.CharField(max_length=10)


#for test

# from django.db import models
# from django.contrib.auth.base_user import BaseUserManager
# from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin


# class CustomUserManager(BaseUserManager):
# 	def create_user(self, phone_number, password=None):
# 		if not phone_number:
# 			raise ValueError('A user phone number is needed.')

# 		if not password:
# 			raise ValueError('A user password is needed.')

# 		phone_number = self.model(phone_number)
# 		user = self.model(phone_number=phone_number)
# 		user.set_password(password)
# 		user.save()
# 		return user

# 	def create_superuser(self, phone_number, password=None):
# 		if not phone_number:
# 			raise ValueError('A user phone number is needed.')

# 		if not password:
# 			raise ValueError('A user password is needed.')

# 		user = self.create_user(phone_number, password)
# 		user.is_superuser = True
# 		user.is_staff = True
# 		user.save()
# 		return user


# class User(models.Model):
# 	user_id = models.AutoField(primary_key=True)
# 	#email = models.EmailField(max_length=100, unique=True)
# 	phone_number = models.CharField(max_length=100)
# 	is_active = models.BooleanField(default=True)
# 	is_staff = models.BooleanField(default=False)
# 	date_joined = models.DateField(auto_now_add=True)
# 	USERNAME_FIELD = 'phone_number'
# 	#REQUIRED_FIELDS = ['username']
# 	objects = UserModel()

# 	def __str__(self):
# 		return self.phone_number