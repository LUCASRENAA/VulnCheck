import json
import logging
import subprocess
import os
from rest_framework import viewsets, permissions
from rest_framework.response import Response
from .models import Scan, Vulnerability
from .serializers import ScanSerializer, VulnerabilitySerializer

class ScanViewSet(viewsets.ModelViewSet):
    queryset = Scan.objects.all()
    serializer_class = ScanSerializer
    permission_classes = [permissions.AllowAny]
    http_method_names = ['get', 'post', 'put', 'patch', 'delete']

    def perform_create(self, serializer):
        scan = serializer.save(status='pending')
        scan.status = 'in_progress'
        scan.save()

        file_path = scan.file.path
        file_name = scan.file.name  # Nome relativo do arquivo salvo

        logging.debug(f"Caminho do arquivo para o Trivy: {file_path}")

        try:
            raw_result = self.run_trivy_scan(file_path, scan.technology)
            logging.debug(f"Saída do Trivy: {raw_result}")

            # Processa o JSON para criar vulnerabilidades
            vulnerabilities = self.process_vulnerabilities(raw_result, scan)
            scan.result = raw_result
            scan.status = 'completed'
        except Exception as e:
            scan.error_message = str(e)
            scan.status = 'failed'

        scan.save()

    def run_trivy_scan(self, file_path, technology):
        try:
            # Pega o nome original do arquivo enviado pelo usuário
            original_file_name = os.path.basename(file_path)

            # Define o caminho renomeado, se necessário
            renamed_file_path = file_path

            if technology == "python":
                # Para Python, usamos 'requirements.txt'
                if not file_path.endswith("requirements.txt"):
                    renamed_file_path = os.path.join(os.path.dirname(file_path), "requirements.txt")
                    os.rename(file_path, renamed_file_path)
            else:
                # Para outras tecnologias, mantém o nome original do arquivo
                renamed_file_path = os.path.join(os.path.dirname(file_path), original_file_name)

            # Comando para o Trivy
            command = ['trivy', 'fs', '--format', 'json', renamed_file_path]

            # Executa o comando e captura a saída
            result = subprocess.run(command, capture_output=True, text=True, check=True)
            if not result.stdout.strip():
                raise Exception("A saída do Trivy está vazia. Verifique se o arquivo está correto.")

            return result.stdout  # Retorna o resultado bruto
        except FileNotFoundError:
            raise Exception("Trivy não encontrado. Verifique se está instalado e no PATH.")
        except subprocess.CalledProcessError as e:
            raise Exception(f"Erro ao rodar Trivy: {e.stderr}")
        finally:
            # Opcional: renomeia de volta o arquivo original após o scan, se foi renomeado
            if technology == "python" and os.path.exists(renamed_file_path) and renamed_file_path != file_path:
                os.rename(renamed_file_path, file_path)

    def process_vulnerabilities(self, raw_result, scan):
        try:
            result_json = json.loads(raw_result)
            vulns = []
            for result in result_json.get("Results", []):
                for vulnerability in result.get("Vulnerabilities", []):
                    vuln = Vulnerability.objects.create(
                        scan=scan,
                        cve=vulnerability.get("VulnerabilityID"),
                        package_name=vulnerability.get("PkgName"),
                        severity=vulnerability.get("Severity"),
                        description=vulnerability.get("Description"),
                        remediation=vulnerability.get("PrimaryURL"),
                        vulnerable_version=vulnerability.get("InstalledVersion"),
                        fixed_version=vulnerability.get("FixedVersion"),
                    )
                    vulns.append(vuln)
            return vulns
        except json.JSONDecodeError:
            raise Exception("Erro ao processar o JSON do Trivy.")

class VulnerabilityViewSet(viewsets.ModelViewSet):
    queryset = Vulnerability.objects.all()
    serializer_class = VulnerabilitySerializer
    permission_classes = [permissions.AllowAny]
    http_method_names = ['get', 'post', 'put', 'patch', 'delete']
