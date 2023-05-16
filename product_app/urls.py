from django import views
from django.conf import settings
from django.urls import include, path
from rest_framework import routers
from django.conf.urls.static import static

from product_app.views import CategoryViewSet, PaymentViewSet, PopularProductsAPIView, ProductSearchAPIView, ProductViewSet,CartViewSet,MyOrderViewSet,OrderViewSet,SimilarProductView


router = routers.DefaultRouter()
router.register(r'category', CategoryViewSet)
router.register(r'product', ProductViewSet)
router.register(r'cart', CartViewSet)
router.register(r'myorder',MyOrderViewSet)
router.register(r'order',OrderViewSet)


#router.register('payments/', PaymentViewSet)#check manoj
router.register(r'payments', PaymentViewSet) #check manoj

# router.register(r'rating',RatingViewSet)


urlpatterns = [
   path('', include(router.urls)),
   # path('api/', include('rest_framework.urls', namespace='rest_framework'))
   #path('search/', SearchAPIView.as_view())#check manoj
   path('products/search/', ProductSearchAPIView.as_view()),#check manoj
   #path('payments/', PaymentViewSet.as_view())#check manoj
   path('popular/', PopularProductsAPIView.as_view()),
   path('product/<int:pk>/similar/', SimilarProductView.as_view()),
] + static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)