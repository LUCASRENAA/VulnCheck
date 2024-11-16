from django.db import models

class Scan(models.Model):
    TECHNOLOGY_CHOICES = [
        ('python', 'Python'),
        ('node', 'Node.js'),
        ('java', 'Java'),
        ('ruby', 'Ruby'),
        ('go', 'Go'),
        # Adicione outras tecnologias conforme necessário
    ]
    
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('in_progress', 'In Progress'),
        ('completed', 'Completed'),
        ('failed', 'Failed'),
    ]
    
    technology = models.CharField(max_length=50, choices=TECHNOLOGY_CHOICES)
    file = models.FileField(upload_to='scans/')
    result = models.TextField(blank=True, null=True)  # Para armazenar os resultados do scan
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    error_message = models.TextField(blank=True, null=True)  # Mensagem de erro, se houver

    def __str__(self):
        return f"Scan {self.id} - {self.technology} - {self.status}"

    class Meta:
        ordering = ['-created_at']

class CVE(models.Model):
    cve = models.CharField(max_length=50, unique=True)  # Identificador CVE (Exemplo: CVE-2024-45231)
    package_name = models.CharField(max_length=100)  # Nome do pacote afetado (Exemplo: Django)
    severity = models.CharField(max_length=20)  # Gravidade (Exemplo: MEDIUM, HIGH, CRITICAL)
    description = models.TextField()  # Descrição do problema
    remediation = models.URLField()  # Link para a correção (Exemplo: URL de referência)
    vulnerable_version = models.CharField(max_length=100)  # Versão vulnerável (Exemplo: 3.0.3)
    fixed_version = models.CharField(max_length=100)  # Versão corrigida (Exemplo: 5.1.1)
    
    # CVSS Fields
    cvss_bitnami_score = models.FloatField(null=True, blank=True)
    cvss_bitnami_vector = models.CharField(max_length=255, null=True, blank=True)
    
    cvss_ghsa_score = models.FloatField(null=True, blank=True)
    cvss_ghsa_vector = models.CharField(max_length=255, null=True, blank=True)
    
    cvss_nvd_score = models.FloatField(null=True, blank=True)
    cvss_nvd_vector = models.CharField(max_length=255, null=True, blank=True)
    
    # Data de publicação da vulnerabilidade
    published_at = models.DateTimeField()

    def __str__(self):
        return f"{self.cve} - {self.package_name} ({self.severity})"
    
    class Meta:
        ordering = ['-published_at']



class Vulnerability(models.Model):
    scan = models.ForeignKey('Scan', on_delete=models.CASCADE, related_name="vulnerabilities")
    cve = models.ForeignKey(CVE, on_delete=models.CASCADE, related_name="vulnerabilities")
    
    def __str__(self):
        return f"{self.cve.cve} - {self.cve.package_name} ({self.cve.severity})"
