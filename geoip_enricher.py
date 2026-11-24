class GeoIPEnricher:
    def __init__(self, db_path=None):
        # Local mock lookup table for your specific test IP addresses
        self.mock_db = {
            "198.51.100.12": {"country": "United States", "city": "New York"},
            "203.0.113.5": {"country": "Australia", "city": "Sydney"}
        }

    def get_location(self, ip_address):
        # Instantly mark private networks
        if ip_address.startswith(('192.168.', '10.', '172.16.', '127.0.0.1')) or not ip_address.strip():
            return {"country": "Local Network", "city": "Internal"}
        
        # Pull matching profile or use an external fallback label
        return self.mock_db.get(ip_address, {"country": "External IP", "city": "Unknown"})

    def close(self):
        pass
