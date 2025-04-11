import ipaddress
import re
from bs4 import BeautifulSoup
import requests
from googlesearch import search
import whois
from datetime import date, datetime
from urllib.parse import urlparse
import logging

class FeatureExtraction:
    def __init__(self, url):
        self.url = url
        self.features = []
        self.domain = ""
        self.whois_response = None
        self.urlparse = None
        self.response = None
        self.soup = None

        try:
            self.response = requests.get(url, timeout=5)
            if self.response and self.response.status_code == 200:
                self.soup = BeautifulSoup(self.response.text, 'html.parser')
            else:
                self.response = requests.models.Response() 
                self.response.status_code = 408  
                self.response._content = b"Default Response Content"  
                self.soup = BeautifulSoup("<html><body><p>Default Content</p></body></html>", "html.parser")
        except requests.exceptions.RequestException as e:
            self.response = requests.models.Response() 
            self.response.status_code = 500  
            self.response._content = b"Failed to fetch URL" 
            self.soup = BeautifulSoup("<html><body><p>Default Content</p></body></html>", "html.parser")

        try:
            self.urlparse = urlparse(url)
            self.domain = self.urlparse.netloc
        except:
            pass
        
        try:
            self.whois_response = whois.whois(self.domain)
            logging.info(self.whois_response)
        except:
            self.whois_response = None

        self.extract_features()

    def extract_features(self):
        self.features.append(self.using_ip())
        self.features.append(self.long_url())
        self.features.append(self.short_url())
        self.features.append(self.contains_at_symbol())
        self.features.append(self.redirecting_double_slash())
        self.features.append(self.prefix_suffix())
        self.features.append(self.subdomains())
        self.features.append(self.https_check())
        self.features.append(self.domain_registration_length())
        self.features.append(self.favicon_check())
        self.features.append(self.non_standard_port())
        self.features.append(self.https_in_domain())
        self.features.append(self.request_url())
        self.features.append(self.anchor_url())
        self.features.append(self.links_in_script_tags())
        self.features.append(self.server_form_handler())
        self.features.append(self.info_email())
        self.features.append(self.abnormal_url())
        self.features.append(self.website_forwarding())
        self.features.append(self.status_bar_customization())
        self.features.append(self.disable_right_click())
        self.features.append(self.using_popup_window())
        self.features.append(self.iframe_redirection())
        self.features.append(self.age_of_domain())
        self.features.append(self.dns_recording())
        self.features.append(self.website_traffic())
        self.features.append(self.page_rank())
        self.features.append(self.google_index())
        self.features.append(self.links_pointing_to_page())
        self.features.append(self.stats_report())

    # 1. Using IP Address
    def using_ip(self):
        try:
            ipaddress.ip_address(self.url)
            return -1
        except:
            return 1

    # 2. Long URL
    def long_url(self):
        logging.info("Hello")
        return -1 if len(self.url) > 75 else (0 if len(self.url) >= 54 else 1)

    # 3. Shortened URL
    def short_url(self):
        match = re.search(r'bit\.ly|goo\.gl|tinyurl|t\.co|is\.gd|cli\.gs', self.url)
        return -1 if match else 1

    # 4. Contains '@' Symbol
    def contains_at_symbol(self):
        return -1 if "@" in self.url else 1

    # 5. Redirecting with '//'
    def redirecting_double_slash(self):
        return -1 if self.url.rfind('//') > 6 else 1

    # 6. Prefix-Suffix in Domain
    def prefix_suffix(self):
        return -1 if "-" in self.domain else 1

    # 7. Subdomains Count
    def subdomains(self):
        dot_count = self.domain.count('.')
        return -1 if dot_count > 2 else (0 if dot_count == 2 else 1)

    # 8. HTTPS in URL
    def https_check(self):
        return 1 if self.url.startswith("https") else -1

    # 9. Domain Registration Length
    def domain_registration_length(self):
        try:
            expiration_date = self.whois_response.expiration_date
            creation_date = self.whois_response.creation_date
            if isinstance(expiration_date, list):
                expiration_date = expiration_date[0]
            if isinstance(creation_date, list):
                creation_date = creation_date[0]

            age = (expiration_date.year - creation_date.year) * 12 + (expiration_date.month - creation_date.month)
            return 1 if age >= 12 else -1
        except:
            return -1

    # 10. Favicon Check
    def favicon_check(self):
        try:
            for link in self.soup.find_all('link', href=True):
                if self.domain in link['href']:
                    return 1
            return -1
        except:
            return -1

    # 11. Non-Standard Port
    def non_standard_port(self):
        return -1 if ":" in self.domain else 1

    # 12. HTTPS in Domain Name
    def https_in_domain(self):
        return -1 if "https" in self.domain else 1

    # 13. Request URL
    def request_url(self):
        return -1 if self.soup and len(self.soup.find_all(['img', 'audio', 'embed', 'iframe'])) > 10 else 1

    # 14. Anchor URL
    def anchor_url(self):
        return -1 if self.soup and len(self.soup.find_all('a', href=True)) > 10 else 1

    # 15. Links in Script Tags
    def links_in_script_tags(self):
        return -1 if self.soup and len(self.soup.find_all(['script', 'link'], src=True)) > 10 else 1

    # 16. Server Form Handler
    def server_form_handler(self):
        return -1 if self.soup and len(self.soup.find_all('form', action=True)) > 5 else 1

    # 17. Info Email
    def info_email(self):
        return -1 if re.findall(r"[mail\(\)|mailto:?]", self.url) else 1

    # 18. Abnormal URL
    def abnormal_url(self):
        return -1 if self.response and self.response.text != self.whois_response else 1

    # 19. Website Forwarding
    def website_forwarding(self):
        return -1 if self.response and len(self.response.history) > 2 else 1

    # 20. Status Bar Customization
    def status_bar_customization(self):
        return -1 if re.findall(r"<script>.+onmouseover.+</script>", self.response.text) else 1

    # 21. Disable Right Click
    def disable_right_click(self):
        return -1 if re.findall(r"event.button ?== ?2", self.response.text) else 1

    # 22. Using Popup Window
    def using_popup_window(self):
        return -1 if re.findall(r"alert\(", self.response.text) else 1

    # 23. Iframe Redirection
    def iframe_redirection(self):
        return -1 if re.findall(r"<iframe>|<frameBorder>", self.response.text) else 1

    # 24. Age of Domain
    def age_of_domain(self):
        try:
            return 1 if self.whois_response.creation_date and (date.today().year - self.whois_response.creation_date.year) > 1 else -1
        except:
            return -1

    # 25. DNS Recording
    def dns_recording(self):
        return 1 if self.whois_response else -1

    # 26. Website Traffic (Uses Alexa)
    def website_traffic(self):
        return -1  # Placeholder, as Alexa API is not available

    # 27. Page Rank
    def page_rank(self):
        return -1  # Placeholder for future implementation

    # 28. Google Index
    def google_index(self):
        try:
            return 1 if search(self.url, num_results=1) else -1
        except:
            return -1

    # 29. Links Pointing to Page
    def links_pointing_to_page(self):
        return 1 if self.soup and len(self.soup.find_all('a', href=True)) > 5 else -1

    # 30. Stats Report
    def stats_report(self):
        return 1  # Placeholder

    def getFeaturesList(self):
        return self.features
