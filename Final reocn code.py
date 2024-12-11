import socket
import threading
import nmap
import barcode
from barcode.writer import ImageWriter
import qrcode
from qrcode import constants
import random
import string
import itertools
import phonenumbers
from phonenumbers import geocoder, carrier
import os
import subprocess
import sys
import re

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def validate_ip(ip):
    try:
        socket.inet_aton(ip)
        return True
    except socket.error:
        return False

def validate_network_range(network):
    pattern = r'^(\d{1,3}\.){3}\d{1,3}/\d{1,2}$'
    return bool(re.match(pattern, network))

def main():
    while True:
        clear_screen()
        print("\n=== Recon Automation for Web Pentesting ===")
        print("1. IP Scanner")
        print("2. Port Scanner")
        print("3. Barcode Generator")
        print("4. QR Code Generator")
        print("5. Password Generator")
        print("6. Wordlist Generator")
        print("7. Phone Number Information")
        print("8. Subdomain Checker")
        print("10. Exit")

        try:
            choice = input("\nEnter your choice (1-10): ")

            if choice == "1":
                network = input("Enter the network range (e.g., 192.168.1.0/24): ")
                if not validate_network_range(network):
                    print("Invalid network range format!")
                    continue
                print("\nScanning... This might take a while.")
                ip_list = ip_scanner(network)
                print("\nActive IP addresses:")
                for ip in ip_list:
                    print(ip)

            elif choice == "2":
                host = input("\nEnter the IP address of the target: ")
                if not validate_ip(host):
                    print("Invalid IP address!")
                    continue
                port_scanner(host)

            elif choice == "3":
                data = input("Enter the data for the barcode: ")
                print("\nAvailable barcode types:")
                print("1. code39")
                print("2. code128")
                print("3. ean13")
                print("4. ean8")
                barcode_type = input("Enter the barcode type: ")
                barcode_types = {'1': 'code39', '2': 'code128', '3': 'ean13', '4': 'ean8'}
                if barcode_type not in barcode_types:
                    print("Invalid barcode type!")
                    continue
                generate_barcode(data, barcode_types[barcode_type])
                print(f"Barcode image saved as {data}_{barcode_types[barcode_type]}.png")

            elif choice == "4":
                data = input("Enter the data for the QR code: ")
                filename = input("Enter the filename for the QR code image (e.g., qr_code.png): ")
                if not filename.endswith('.png'):
                    filename += '.png'
                generate_qr(data, filename)
                print(f"QR code image saved as {filename}")

            elif choice == "5":
                try:
                    length = int(input("Enter the desired length for the password (8-50, default: 12): ") or "12")
                    if length < 8 or length > 50:
                        print("Password length must be between 8 and 50!")
                        continue
                    password = generate_password(length)
                    print(f"\nGenerated password: {password}")
                except ValueError:
                    print("Please enter a valid number!")

            elif choice == "6":
                words = input("Enter the words to use in the wordlist (separated by spaces): ").split()
                if not words:
                    print("Please enter at least one word!")
                    continue
                filename = input("Enter the filename for the wordlist (e.g., wordlist.txt): ")
                if not filename.endswith('.txt'):
                    filename += '.txt'
                generate_wordlist(words, filename)
                print(f"Wordlist saved as {filename}")

            elif choice == "7":
                number = input("Enter the phone number (e.g., +919234567890): ")
                phone_info(number)

            elif choice == "8":
                domain = input("Enter the domain name (e.g., example.com): ")
                if not re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', domain):
                    print("Invalid domain format!")
                    continue
                subdomain_checker(domain)

            elif choice == "10":
                print("\nExiting program...")
                sys.exit(0)

            else:
                print("Invalid choice. Please try again.")

            input("\nPress Enter to continue...")

        except KeyboardInterrupt:
            print("\nOperation cancelled by user.")
            input("\nPress Enter to continue...")
        except Exception as e:
            print(f"\nAn error occurred: {str(e)}")
            input("\nPress Enter to continue...")

def ip_scanner(network):
    try:
        ip_list = []
        nm = nmap.PortScanner()
        nm.scan(hosts=network, arguments='-sn')
        for host in nm.all_hosts():
            if nm[host].state() == "up":
                ip_list.append(host)
        return ip_list
    except Exception as e:
        print(f"Error scanning network: {str(e)}")
        return []

def port_scanner(target):
    try:
        nm = nmap.PortScanner()
        print("\nScanning ports... This might take a while.")
        nm.scan(target, arguments='-p- -sS -sV -T4')
        
        for host in nm.all_hosts():
            print(f"\nHost: {host} ({nm[host].hostname() if nm[host].hostname() else 'No hostname'})")
            print(f"State: {nm[host].state()}")
            
            for proto in nm[host].all_protocols():
                print(f"\nProtocol: {proto}")
                ports = nm[host][proto].keys()
                for port in ports:
                    service = nm[host][proto][port]
                    print(f"Port: {port}\tState: {service['state']}\tService: {service['name']}\tVersion: {service['version']}")
    except Exception as e:
        print(f"Error scanning ports: {str(e)}")

def generate_barcode(data, barcode_type='code128'):
    try:
        code = barcode.get_barcode_class(barcode_type)
        code = code(data, writer=ImageWriter())
        filename = f'{data}_{barcode_type}'
        code.save(filename)
    except Exception as e:
        print(f"Error generating barcode: {str(e)}")

def generate_qr(data, filename):
    try:
        qr = qrcode.QRCode(
            version=1,
            error_correction=constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        qr.add_data(data)
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white")
        img.save(filename)
    except Exception as e:
        print(f"Error generating QR code: {str(e)}")

def generate_password(length=12):
    try:
        lowercase = string.ascii_lowercase
        uppercase = string.ascii_uppercase
        digits = string.digits
        special = string.punctuation
        
        # Ensure at least one character from each category
        password = [
            random.choice(lowercase),
            random.choice(uppercase),
            random.choice(digits),
            random.choice(special)
        ]
        
        # Fill the rest randomly
        for _ in range(length - 4):
            password.append(random.choice(lowercase + uppercase + digits + special))
        
        # Shuffle the password
        random.shuffle(password)
        return ''.join(password)
    except Exception as e:
        print(f"Error generating password: {str(e)}")
        return None

def generate_wordlist(words, filename):
    try:
        with open(filename, 'w') as f:
            for length in range(1, 4):  # Generate combinations of 1 to 3 words
                for combination in itertools.product(words, repeat=length):
                    f.write(''.join(combination) + '\n')
    except Exception as e:
        print(f"Error generating wordlist: {str(e)}")

def phone_info(number):
    try:
        # Remove spaces and ensure the number starts with '+'
        number = number.strip().replace(" ", "")
        if not number.startswith('+'):
            number = '+' + number

        parsed_number = phonenumbers.parse(number)
        
        if not phonenumbers.is_valid_number(parsed_number):
            print("Invalid phone number format!")
            return

        # Get country information
        country = geocoder.description_for_number(parsed_number, "en")
        
        # Get carrier information
        provider = carrier.name_for_number(parsed_number, "en")
        
        # Get region information
        region = geocoder.description_for_number(parsed_number, "en")
        
        # Get number type
        number_type = phonenumbers.number_type(parsed_number)
        number_type_dict = {
            0: "FIXED_LINE",
            1: "MOBILE",
            2: "FIXED_LINE_OR_MOBILE",
            3: "TOLL_FREE",
            4: "PREMIUM_RATE",
            5: "SHARED_COST",
            6: "VOIP",
            7: "PERSONAL_NUMBER",
            8: "PAGER",
            9: "UAN",
            10: "UNKNOWN"
        }
        
        print("\nPhone Number Information:")
        print(f"Formatted Number: {phonenumbers.format_number(parsed_number, phonenumbers.PhoneNumberFormat.INTERNATIONAL)}")
        print(f"Country: {country if country else 'Unknown'}")
        print(f"Region: {region if region else 'Unknown'}")
        print(f"Provider: {provider if provider else 'Unknown'}")
        print(f"Number Type: {number_type_dict.get(number_type, 'Unknown')}")
        print(f"Valid Number: Yes")
        print(f"Possible Number: {phonenumbers.is_possible_number(parsed_number)}")
        
    except Exception as e:
        print(f"Error processing phone number: {str(e)}")
        print("Please ensure you're using the correct format (e.g., +919234567890)")

def subdomain_checker(domain):
    try:
        print(f"\nChecking subdomains for {domain}...")
        # First try sublist3r
        try:
            subprocess.run(["sublist3r", "-d", domain], check=True)
        except FileNotFoundError:
            print("Sublist3r not found. Performing basic DNS lookup...")
            # Fallback to basic DNS lookup
            import dns.resolver
            common_subdomains = ['www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'webdisk', 'ns2', 'cpanel', 'whm', 'autodiscover', 'autoconfig']
            for subdomain in common_subdomains:
                try:
                    test_domain = f"{subdomain}.{domain}"
                    dns.resolver.resolve(test_domain, 'A')
                    print(f"Found subdomain: {test_domain}")
                except dns.resolver.NXDOMAIN:
                    continue
                except dns.resolver.NoAnswer:
                    continue
    except Exception as e:
        print(f"Error checking subdomains: {str(e)}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nProgram terminated by user.")
        sys.exit(0)
    except Exception as e:
        print(f"\nAn unexpected error occurred: {str(e)}")
        sys.exit(1)