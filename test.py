from whois import whois

whois_obj = whois.Whois('nixweb.com')
print whois_obj.info()
print whois_obj.is_available()