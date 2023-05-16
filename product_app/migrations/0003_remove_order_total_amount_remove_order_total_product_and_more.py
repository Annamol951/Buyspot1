# Generated by Django 4.2 on 2023-05-08 06:08

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('product_app', '0002_initial'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='order',
            name='total_amount',
        ),
        migrations.RemoveField(
            model_name='order',
            name='total_product',
        ),
        migrations.RemoveField(
            model_name='order',
            name='transaction_id',
        ),
        migrations.AddField(
            model_name='order',
            name='order_id',
            field=models.IntegerField(default=2),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name='order',
            name='order_tracking',
            field=models.CharField(default=3, max_length=40),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name='order',
            name='payment_mode',
            field=models.CharField(default=4, max_length=30),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name='order',
            name='price',
            field=models.IntegerField(default=1),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name='order',
            name='rating',
            field=models.IntegerField(default=0),
        ),
    ]
