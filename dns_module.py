# modules/dns_module.py
"""
DNS Enumeration Module for Reconnaissance Tool

Description: Performs DNS record enumeration including A, MX, TXT, NS records
"""

import dns.resolver
import dns.reversename
import socket
import time
from typing import Dict, List, Optional, Tuple
import concurrent.futures
from datetime import datetime
import logging
import argparse

class DNSModule:
    """
    DNS enumeration module that queries various DNS records for a given domain.
    """
    
    # Common DNS record types to query
    DEFAULT_RECORD_TYPES = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA']
    
    def __init__(self, verbose: bool = False, logger=None):
        """
        Initialize DNS module.
        
        Args:
            verbose (bool): Enable verbose logging
            logger: Optional logger instance (for integration)
        """
        if logger:
            self.logger = logger
        else:
            # Create standalone logger if not provided
            self.logger = self._setup_standalone_logger(verbose)
        
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = 10
        self.resolver.lifetime = 10
        
    def _setup_standalone_logger(self, verbose: bool) -> logging.Logger:
        """Setup logger for standalone execution."""
        logger = logging.getLogger('dns_module')
        
        if verbose:
            logger.setLevel(logging.DEBUG)
        else:
            logger.setLevel(logging.INFO)
            
        # Create console handler
        handler = logging.StreamHandler()
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        handler.setFormatter(formatter)
        
        # Avoid duplicate handlers
        if not logger.handlers:
            logger.addHandler(handler)
            
        return logger
    
    def query_record(self, domain: str, record_type: str) -> List[str]:
        """
        Query a specific DNS record type for a domain.
        
        Args:
            domain (str): Domain to query
            record_type (str): DNS record type (A, MX, TXT, etc.)
            
        Returns:
            List[str]: List of record values
        """
        records = []
        try:
            answers = self.resolver.resolve(domain, record_type)
            for rdata in answers:
                if record_type == 'A':
                    records.append(rdata.address)
                elif record_type == 'AAAA':
                    records.append(rdata.address)
                elif record_type == 'MX':
                    records.append(f"{rdata.preference} {rdata.exchange}")
                elif record_type == 'NS':
                    records.append(str(rdata.target))
                elif record_type == 'TXT':
                    # TXT records can have multiple strings
                    txt_data = ' '.join([s.decode() if isinstance(s, bytes) else s for s in rdata.strings])
                    records.append(txt_data)
                elif record_type == 'CNAME':
                    records.append(str(rdata.target))
                elif record_type == 'SOA':
                    records.append(str(rdata))
                else:
                    records.append(str(rdata))
                    
            self.logger.debug(f"Successfully queried {record_type} records for {domain}")
            
        except dns.resolver.NoAnswer:
            self.logger.debug(f"No {record_type} records found for {domain}")
        except dns.resolver.NXDOMAIN:
            self.logger.warning(f"Domain {domain} does not exist (NXDOMAIN)")
        except dns.resolver.Timeout:
            self.logger.error(f"DNS query timeout for {record_type} records of {domain}")
        except dns.resolver.NoNameservers:
            self.logger.error(f"No nameservers available for {domain}")
        except Exception as e:
            self.logger.error(f"Error querying {record_type} records for {domain}: {str(e)}")
            
        return records
    
    def enumerate_all_records(self, domain: str, record_types: Optional[List[str]] = None) -> Dict[str, List[str]]:
        """
        Enumerate multiple DNS record types for a domain.
        
        Args:
            domain (str): Domain to query
            record_types (List[str]): List of record types to query
            
        Returns:
            Dict[str, List[str]]: Dictionary with record types as keys and values as lists
        """
        if record_types is None:
            record_types = self.DEFAULT_RECORD_TYPES
            
        results = {}
        
        self.logger.info(f"Starting DNS enumeration for {domain}")
        start_time = time.time()
        
        # Use thread pool for concurrent queries
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            future_to_type = {
                executor.submit(self.query_record, domain, rtype): rtype 
                for rtype in record_types
            }
            
            for future in concurrent.futures.as_completed(future_to_type):
                rtype = future_to_type[future]
                try:
                    records = future.result()
                    if records:
                        results[rtype] = records
                        self.logger.info(f"Found {len(records)} {rtype} record(s)")
                except Exception as e:
                    self.logger.error(f"Failed to get {rtype} records: {str(e)}")
        
        # Additional functionality: Reverse DNS for IP addresses found
        if 'A' in results:
            results['PTR'] = self.reverse_dns_lookup(results['A'])
            
        elapsed_time = time.time() - start_time
        self.logger.info(f"DNS enumeration completed in {elapsed_time:.2f} seconds")
        
        return results
    
    def reverse_dns_lookup(self, ip_addresses: List[str]) -> List[str]:
        """
        Perform reverse DNS lookup for IP addresses.
        
        Args:
            ip_addresses (List[str]): List of IP addresses
            
        Returns:
            List[str]: List of PTR records
        """
        ptr_records = []
        
        for ip in ip_addresses:
            try:
                # Validate IP address
                socket.inet_aton(ip)
                hostname, _, _ = socket.gethostbyaddr(ip)
                ptr_records.append(f"{ip} -> {hostname}")
                self.logger.debug(f"Reverse DNS for {ip}: {hostname}")
            except socket.error:
                self.logger.debug(f"Invalid IP address: {ip}")
            except socket.herror:
                self.logger.debug(f"No PTR record found for {ip}")
            except Exception as e:
                self.logger.error(f"Error in reverse DNS lookup for {ip}: {str(e)}")
                
        return ptr_records
    
    def get_nameservers(self, domain: str) -> List[str]:
        """
        Get nameservers for a domain.
        
        Args:
            domain (str): Domain to query
            
        Returns:
            List[str]: List of nameserver hostnames
        """
        try:
            answers = self.resolver.resolve(domain, 'NS')
            nameservers = [str(ns.target) for ns in answers]
            self.logger.info(f"Found {len(nameservers)} nameserver(s) for {domain}")
            return nameservers
        except Exception as e:
            self.logger.error(f"Error getting nameservers for {domain}: {str(e)}")
            return []
    
    def get_mx_records(self, domain: str) -> List[Tuple[int, str]]:
        """
        Get MX records with priority for a domain.
        
        Args:
            domain (str): Domain to query
            
        Returns:
            List[Tuple[int, str]]: List of tuples (priority, mail server)
        """
        mx_records = []
        try:
            answers = self.resolver.resolve(domain, 'MX')
            for rdata in answers:
                mx_records.append((rdata.preference, str(rdata.exchange)))
            self.logger.info(f"Found {len(mx_records)} MX record(s) for {domain}")
        except Exception as e:
            self.logger.error(f"Error getting MX records for {domain}: {str(e)}")
            
        # Sort by priority
        mx_records.sort(key=lambda x: x[0])
        return mx_records
    
    def get_txt_records(self, domain: str) -> List[str]:
        """
        Get all TXT records for a domain.
        
        Args:
            domain (str): Domain to query
            
        Returns:
            List[str]: List of TXT record values
        """
        txt_records = []
        try:
            answers = self.resolver.resolve(domain, 'TXT')
            for rdata in answers:
                # Join multiple strings in TXT record
                txt_data = ' '.join([s.decode() if isinstance(s, bytes) else s for s in rdata.strings])
                txt_records.append(txt_data)
            self.logger.info(f"Found {len(txt_records)} TXT record(s) for {domain}")
        except Exception as e:
            self.logger.error(f"Error getting TXT records for {domain}: {str(e)}")
            
        return txt_records
    
    def get_custom_resolver(self, nameserver: str) -> dns.resolver.Resolver:
        """
        Create a resolver with custom nameserver.
        
        Args:
            nameserver (str): Custom nameserver IP address
            
        Returns:
            dns.resolver.Resolver: Configured resolver
        """
        resolver = dns.resolver.Resolver()
        resolver.nameservers = [nameserver]
        resolver.timeout = 10
        resolver.lifetime = 10
        return resolver
    
    def format_results(self, results: Dict[str, List[str]]) -> str:
        """
        Format DNS results for display or reporting.
        
        Args:
            results (Dict[str, List[str]]): DNS results dictionary
            
        Returns:
            str: Formatted results string
        """
        output = "=" * 60 + "\n"
        output += "DNS ENUMERATION RESULTS\n"
        output += "=" * 60 + "\n\n"
        
        for record_type, values in results.items():
            output += f"{record_type} Records:\n"
            output += "-" * 40 + "\n"
            if values:
                for i, value in enumerate(values, 1):
                    output += f"  {i}. {value}\n"
            else:
                output += "  No records found\n"
            output += "\n"
            
        return output
    
    def run(self, domain: str, record_types: Optional[List[str]] = None) -> Dict[str, List[str]]:
        """
        Main method to run DNS enumeration.
        
        Args:
            domain (str): Domain to enumerate
            record_types (List[str]): Specific record types to query
            
        Returns:
            Dict[str, List[str]]: Dictionary of DNS records
        """
        self.logger.info(f"Running DNS module for domain: {domain}")
        
        # Validate domain format
        if not self._validate_domain(domain):
            self.logger.error(f"Invalid domain format: {domain}")
            return {}
            
        # Perform DNS enumeration
        results = self.enumerate_all_records(domain, record_types)
        
        # Log summary
        total_records = sum(len(v) for v in results.values())
        self.logger.info(f"DNS enumeration complete. Found {total_records} total records across {len(results)} record types")
        
        return results
    
    def _validate_domain(self, domain: str) -> bool:
        """
        Validate domain name format.
        
        Args:
            domain (str): Domain to validate
            
        Returns:
            bool: True if valid, False otherwise
        """
        # Basic validation - can be enhanced
        if not domain or len(domain) > 255:
            return False
            
        # Check for valid characters
        allowed = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-")
        if not all(c in allowed for c in domain):
            return False
            
        # Check for at least one dot
        if '.' not in domain:
            return False
            
        return True
    
    def get_results_for_reporting(self, results: Dict[str, List[str]]) -> Dict:
        """
        Prepare results for reporting module integration.
        
        Args:
            results (Dict[str, List[str]]): DNS results
            
        Returns:
            Dict: Structured data for reporting
        """
        report_data = {
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'domain': '',
            'records': {},
            'summary': {}
        }
        
        if results:
            # Count total records
            total = sum(len(v) for v in results.values())
            report_data['summary'] = {
                'total_records': total,
                'record_types': len(results),
                'status': 'completed'
            }
            
            # Add all records
            report_data['records'] = results
            
        return report_data


# Standalone execution for testing
def main():
    parser = argparse.ArgumentParser(description="DNS Enumeration Module")
    parser.add_argument("domain", help="Domain to enumerate")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose logging")
    parser.add_argument("-t", "--types", nargs="+", 
                       default=['A', 'MX', 'NS', 'TXT'],
                       help="DNS record types to query")
    parser.add_argument("-n", "--nameserver", help="Use custom nameserver")
    parser.add_argument("-o", "--output", help="Output file for results")
    
    args = parser.parse_args()
    
    # Initialize and run module
    dns_module = DNSModule(verbose=args.verbose)
    
    # Set custom nameserver if provided
    if args.nameserver:
        dns_module.resolver = dns_module.get_custom_resolver(args.nameserver)
    
    results = dns_module.run(args.domain, args.types)
    
    # Print formatted results
    output = dns_module.format_results(results)
    print(output)
    
    # Save to file if requested
    if args.output:
        with open(args.output, 'w') as f:
            f.write(output)
        print(f"\nResults saved to {args.output}")


if __name__ == "__main__":
    main()
