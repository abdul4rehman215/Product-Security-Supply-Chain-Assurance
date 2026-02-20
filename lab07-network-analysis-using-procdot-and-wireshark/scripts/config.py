# File: config.py

CAPTURE_INTERFACE = 'any'
CAPTURE_DURATION = 300
CAPTURE_FILTER = 'not port 22'

HTTP_ENDPOINTS = [
    'http://httpbin.org/get',
    'http://httpbin.org/post'
]

DNS_DOMAINS = [
    'product-security.example.com',
    'api.security-scanner.com'
]

ANOMALY_THRESHOLD = 3
COMMON_PORTS = {80, 443, 53, 22}

OUTPUT_DIR = './analysis_output'
GENERATE_VISUALIZATIONS = True
