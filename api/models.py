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


class Vulnerability(models.Model):
    scan = models.ForeignKey(Scan, on_delete=models.CASCADE, related_name="vulnerabilities")
    cve = models.CharField(max_length=50, blank=True, null=True)  # Ex.: CVE-2022-1234
    package_name = models.CharField(max_length=100)  # Pacote afetado
    severity = models.CharField(max_length=20)  # Ex.: HIGH, CRITICAL
    description = models.TextField(blank=True, null=True)
    remediation = models.TextField(blank=True, null=True)  # Como corrigir
    vulnerable_version = models.CharField(max_length=100, blank=True, null=True)  # Ex.: <2.0.0
    fixed_version = models.CharField(max_length=100, blank=True, null=True)  # Ex.: >=2.0.1

    def __str__(self):
        return f"{self.cve} - {self.package_name} ({self.severity})"
