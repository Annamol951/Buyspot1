from rest_framework import serializers
from product_app.models import Category, Product,Cart,MyOrder,Order

class CategorySerializer(serializers.ModelSerializer):
    class Meta:
        model = Category
        fields = ['id', 'name']

class   ProductSerializer(serializers.ModelSerializer):
    # rating = serializers.StringRelatedField()
    class Meta:
        model =Product
        fields = ['id', 'item','Image', 'price','offer','size', 'category', 'stock', 'rating','description']
        #Fields = '__all__'

# class RatingSerializer(serializers.ModelSerializer):
#     #  rating = serializers.StringRelatedField() 
#      class Meta:
#         model = Item_Rating
#         fields = ['item', 'one', 'two','three', 'four', 'five']     

class CartSerializer(serializers.ModelSerializer):
    class Meta:
        model =Cart
        fields =['id','item','image','size','quantity', 'price', 'total']

class MyOrderSerializer(serializers.ModelSerializer):
    class Meta:
        model =MyOrder    

        fields =['user','order_id','ordered_item','quantity','price','ordered_date','sold_to']


class OrderSerializer(serializers.HyperlinkedModelSerializer):
    class Meta:
        model = Order
        fields = ('product', 'order_id','payment_mode','rating','order_tracking','price','created_at','updated_at')

#check manoj

from rest_framework import serializers
from .models import Payment

class PaymentSerializer(serializers.ModelSerializer):
    class Meta:
        model = Payment
        fields = ('id', 'customer_name', 'order_id', 'amount', 'payment_date', 'payment_status', 'payment_mode', 'Payment_id')

 
 #check manoj

from rest_framework import serializers
from .models import Product


class ProductSerializer(serializers.ModelSerializer):
    class Meta:
        model = Product
        fields = '__all__'





        
