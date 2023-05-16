from django.contrib import admin
from .models import Product,Category,Cart,MyOrder,Order


# Register your models here.
admin.site.register(Product)
admin.site.register(Category)
admin.site.register(Cart)
admin.site.register(MyOrder)
admin.site.register(Order)





# admin.site.register(Order)
# admin.site.register(OrderProduct)
# admin.site.register(BillingAddress)