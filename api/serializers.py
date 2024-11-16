# scanner/serializers.py

from rest_framework import serializers
from .models import Scan,Vulnerability,CVE

class ScanSerializer(serializers.ModelSerializer):
    class Meta:
        model = Scan
        fields = '__all__'

    # Validação do arquivo para garantir que o tipo de arquivo seja compatível
    def validate_file(self, value):
        file_extension = value.name.split('.')[-1]
        allowed_extensions = ['txt', 'json']  # Pode adicionar outros tipos de arquivo, como .xml, .gem, etc.
        
        if file_extension not in allowed_extensions:
            raise serializers.ValidationError("Formato de arquivo inválido. Aceito apenas .txt e .json.")
        
        return value
    
class VulnerabilitySerializer(serializers.ModelSerializer):
    class Meta:
        model = Vulnerability
        fields = '__all__'

    
class CVESerializer(serializers.ModelSerializer):
    class Meta:
        model = CVE
        fields = '__all__'
