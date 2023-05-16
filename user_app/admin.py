from django.contrib import admin

# Register your models here.

#check
from django.db import models
from . import models


admin.site.register(models.UserModel)
