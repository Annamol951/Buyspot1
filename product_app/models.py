from django.db import models
# from django.urls import reverse
from django.contrib.auth.models import User
from django.conf import settings


# from django.contrib.auth import get_user_model



# Create your models here.

class Category(models.Model):
    name = models.CharField(max_length=100)

    def __str__(self):
        return self.name

class Product(models.Model):
    item = models.CharField(max_length=100)
    Image = models.ImageField(upload_to='product_images/')
    price = models.FloatField(default=0)
    offer = models.IntegerField(default=0)
    size = models.CharField(max_length=30)
    category = models.ForeignKey(Category, on_delete=models.CASCADE)
    stock = models.CharField(max_length=50)
    rating = models.IntegerField(default=0)
    description = models.TextField()
    # similar = models.ManyToManyField(item)

    def __str__(self):
        return self.item
    # def similar_products(self):
    #     return self.similar.all()
    
class Cart(models.Model):
    item = models.CharField(max_length=100)  
    image = models.ImageField(upload_to='product/images/') 
    size = models.CharField(max_length=20)
    quantity = models.IntegerField(default=0)
    price = models.FloatField(default=0)
    total = models.FloatField(default=0)

    # @property
    # def total_price(self):
    #     return self.quantity * self.item.price

#     STATUS_CHOICES = (
#     ('Pending', 'Pending'),
#     ('Accepted', 'Accepted'),
#     ('Packed', 'Packed'),
#     ('On The Way', 'On The Way'),
#     ('Delivered', 'Delivered'),
#     ('Cancelled', 'Cancelled')
# )

class MyOrder(models.Model):
    ''' a list of ordered items '''

    user = models.ForeignKey(settings.AUTH_USER_MODEL,on_delete=models.CASCADE)        
    order_id = models.IntegerField()                                
    ordered_item = models.CharField(max_length=100)                           
    quantity = models.IntegerField()         
    price = models.IntegerField()                                              
    ordered_date = models.DateTimeField(max_length=100) 
    sold_to = models.CharField(max_length=50)      

    def __str__(self):
        return f"{self.quantity} of {self.item.title}"

    def get_total_product_price(self):
        ''' calculates the total price of items '''
        # if has a discount price
        if self.product.discounted_price:
            return self.quantity * self.product.discounted_price
        return self.quantity * self.product.price
    

class Order(models.Model):
    # user = models.ForeignKey(User, on_delete=models.CASCADE, null=True, blank=True)

    product = models.CharField(max_length=500)
    order_id = models.IntegerField() 
    payment_mode = models.CharField(max_length=30)
    rating = models.IntegerField(default=0)
    order_tracking = models.CharField(max_length=40)
    price = models.IntegerField()
    # transaction_id = models.CharField(max_length=150, default=0)
    # total_amount = models.CharField(max_length=50, default=0)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    # status = models.CharField(
    #     choices=STATUS_CHOICES,
    #     max_length=50,
    #     default="Pending"
    #     )
 
    def __str__(self):
        return self.product
    

# class Item_Rating(models.Model):
#         item = models.ForeignKey(Product, related_name='itemrating',
#                                     on_delete=models.CASCADE)
#         one = models.PositiveIntegerField(default=0, null=True, blank=True)
#         two = models.PositiveIntegerField(default=0, null=True, blank=True)
#         three = models.PositiveIntegerField(default=0, null=True, blank=True)
#         four = models.PositiveIntegerField(default=0, null=True, blank=True)
#         five = models.PositiveIntegerField(default=0, null=True, blank=True)

#         class Meta:
#           ordering = ['item']

#         def __str__(self):
#             # Extract all rating values and return max key.
#             # Reverse this Dict if there is a tie and you want the last key.
#             rating_list = {
#               '1': self.one,
#               '2': self.two,
#               '3': self.three,
#               '4': self.four,
#               '5': self.five
#             }
#             return str(max(rating_list, key=rating_list.get))
  

# class OrderProduct(models.Model):
#     ''' a list of ordered items '''
#     user = models.ForeignKey(User,on_delete=models.CASCADE)                                        
#     product = models.ForeignKey(Product, on_delete=models.CASCADE, null=True)                            
#     quantity = models.IntegerField(default=1)                                                       
#     ordered = models.BooleanField(default=False)                                                    

#     def __str__(self):
#         return f"{self.quantity} of {self.item.title}"

#     def get_total_item_price(self):
#         ''' calculates the total price of items '''
#         # if has a discount price
#         if self.item.discounted_price:
#             return self.quantity * self.item.discounted_price
#         return self.quantity * self.item.price
    

# class Order(models.Model):
    
#     user = models.ForeignKey(User, on_delete=models.CASCADE, null=True)     # user
#     items = models.ManyToManyField(OrderProduct)                               # list of items belonging to user
#     start_date = models.DateTimeField(auto_now_add=True)                    # start of first order
#     ordered_date = models.DateTimeField()                                   # order date
#     ordered = models.BooleanField(default=False)                            # is order

#     billing_address = models.ForeignKey('BillingAddress', on_delete=models.SET_NULL, blank=True, null=True)                            # billing address

#     payment = models.ForeignKey('Payment', on_delete=models.SET_NULL, blank=True, null=True)                                            # pay

#     def __str__(self):
#         return self.user.username

#     def get_final_price(self):
#         ''' gets the final price of purchases '''
#         total = 0
#         for order_item in self.items.all():
#             total += order_item.get_total_item_price()

#         return total
    
# class BillingAddress(models.Model):
#     ''' handling billing address '''
#     user = models.ForeignKey(User, on_delete=models.CASCADE, null=True)     # user
#     street_address = models.CharField(max_length=400)
#     apartment_address = models.CharField(max_length=400)
#     zip_address = models.CharField(max_length=40)

#     def __str__(self):
#         return self.user.username


# class Payment(models.Model):
#     ''' for when a customer pays '''
#     stripe_charge_id = models.CharField(max_length=50)
#     user = models.ForeignKey(User, on_delete=models.SET_NULL, blank=True, null=True)     # user
#     amount = models.DecimalField(max_digits=6, decimal_places=2)
#     timestamp = models.DateField(auto_now_add=True)

#     def __str__(self):
#         return self.user.username    


#check manoj



class Payment(models.Model):
    customer_name = models.CharField(max_length=50)
    order_id = models.IntegerField()
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    payment_date = models.DateTimeField(auto_now_add=True)
    payment_status = models.CharField(max_length=20)
    payment_mode = models.CharField(max_length=20)
    Payment_id = models.IntegerField()


#check manoj

class ProductPopularity(models.Model):
    product = models.ForeignKey(Product, on_delete=models.CASCADE)
    popularity = models.IntegerField(default=0)



