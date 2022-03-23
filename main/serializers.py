from rest_framework import serializers
from .models import User, Gender


class UserApiViewSerial(serializers.Serializer):
    name = serializers.CharField()
    def create(self, validated_data):
        return Gender.objects.create(**validated_data)
    def update(self,instance, validated_data):
        instance.name = validated_data.get('name')
        instance.save()
        return instance