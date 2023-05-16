from django.db import models

# Create your models here.

from django.db import models

# Create your models here.

#check

from django.conf import settings
from django.contrib.auth.models import (
    AbstractBaseUser,
    BaseUserManager,
    Group,
    PermissionsMixin,
)
from django.core.validators import RegexValidator, validate_email
from django.db import models


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
    first_name = models.CharField(max_length=50, null=False, blank=False)
    last_name = models.CharField(max_length=50, null=False, blank=False)
    address = models.TextField(null=False, blank=False)
    
    phone_number = models.CharField(
        unique=True, max_length=10, null=False, blank=False, validators=[phone_regex]
    )
    email = models.EmailField(
        max_length=50,
        blank=False,
        null=False,
        validators=[validate_email],
    )
    otp = models.IntegerField(null=True)
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


