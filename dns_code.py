import dns.resolver

def dns_enumeration(domain):
    record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME']
    results = {}

    for record in record_types:
        try:
            answers = dns.resolver.resolve(domain, record)
            results[record] = [str(rdata) for rdata in answers]
        except Exception:
            results[record] = []

    return results

if __name__ == "__main__":
    target = input("Enter target domain: ")
    dns_info = dns_enumeration(target)
    for record, values in dns_info.items():
        print(f"\n{record} Records:")
        if values:
            for v in values:
                print(f"- {v}")
        else:
            print("- None found")

