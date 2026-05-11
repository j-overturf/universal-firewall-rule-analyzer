"""
Script that analyzes firewall rules and checks for
shadowing, redundancy, and potential optimizations
"""
import ipaddress
import pandas as pd

# ------------ The Firewall Resolver Object ----------
class FirewallResolver:
    """
    The Firewall Resolver object will take the data inside an
    addresses.csv file and a services.csv file and flatten the groups
    and ports into raw data that can be logically analyzed.
    """

    def __init__(self, addr_map, serv_map):
        """
        Initialize the Firewall Resolver object.

        :param addr_map: The dictionary connecting the address objects to IP's.
        :param serv_map: The dictionary connecting service objects to ports.
        """
        # Convert the data from the CSV's into a dictionary for fast lookup.
        self.addr_map = addr_map
        self.serv_map = serv_map

    def resolve_addresses(self, name):
        """
        Recursively resolves an address object name into IP ranges/CIDRs.

        :param name: Name of the address object.
        :return: IP ranges/CIDRs associated with that address object.
        """

        # Check if the name is any or all which translates to 0.0.0.0/0
        if name.lower() in ["any", "all", ""]:
            return [ipaddress.ip_network('0.0.0.0/0')]

        # Check for multiple source or destinaiton names.
        names = [n.strip() for n in str(name).split(" ") if n.strip()]

        # Check if there are multiple names.
        if len(names) > 1:
            total_results = []
            # Recursively call the function for each source or destination object.
            for n in names:
                total_results.extend(self.resolve_addresses(n))

            return total_results

        # Check if the object is not a name but already a raw CIDR
        try:
            return [ipaddress.ip_network(name, strict=False)]
        # If it is not a raw CIDR, continue to decoding the name.
        except ValueError:
            pass

        # Check if the name is present inside the map, if not return an empty array.
        if name not in self.addr_map:
            return []

        # Get the item from the map since it must be present.
        item = self.addr_map[name]

        # Declare the variable that will hold the IP ranges/CIDR results.
        results = []

        # Check if the address object is of Group type, this will require recursion on
        # each object inside the Group.
        if item["type"].lower() == "group":
            # Retrieve the members of the group.
            members = [m.strip() for m in item["value"].split(" ")]

            # For each member in the group, recursively resolve their addresses.
            for member in members:
                results.extend(self.resolve_addresses(member))

        else:
            # If it is not a group, handle it like a standard CIDR, range, or single host.
            value = item["value"]
            # Attempt to grab the IP CIDR, range, or single host.
            try:
                # If there is a dash present it represents a range.
                if "-" in value:
                    start, end = value.split("-")

                    # Convert the range into a list of CIDRs
                    summary = [ip for ip in ipaddress.summarize_address_range(
                        ipaddress.IPv4Address(start.strip()),
                        ipaddress.IPv4Address(end.strip())
                    )]

                    # Put the summary into the results.
                    results.extend(summary)
                else:
                    # If it is not a range, append the host.
                    results.append(ipaddress.ip_network(value.strip(), strict=False))
            # If it fails to resolve the address catch the exception.
            except ValueError:
                print(f"Error in resolving address: {value}")

        # Return the results.
        return results

    def resolve_services(self, name):
        """
        Recursively resolves a service object name into IP ranges/CIDRs.

        :param name: Name of the service object.
        :return: Tuple of all protocol and port
        """
        # Check if the name is any or all which translates to protocol any, 0-65535.
        if name.lower() in ["any", "all", ""]:
            return [("ANY", 0, 65535)]

        # Check if the name is just a singular port.
        if name.isdigit():
            # Return results of it being a TCP and UDP.
            return [('TCP', int(name), int(name)), ('UDP', int(name), int(name))]

        # Check if it's a raw range (e.g., "8000-8080").
        if '-' in name and all(part.strip().isdigit() for part in name.split('-')):
            # Return the TCP and UDP of the results.
            start, end = name.split('-')
            return [('TCP', int(start), int(end)), ('UDP', int(start), int(end))]

        # Check if the name is present inside the map, if not return an empty array.
        if name not in self.serv_map:
            return []

        # Get the item from the map since it must be present.
        item = self.serv_map[name]

        # Declare the variable that will hold the IP ranges/CIDR results.
        results = []

        # Handle the service groups
        if item["protocol"].lower() == "group":
            # Retrieve the members of the group.
            members = [m.strip() for m in item["port"].split(" ")]

            # For each member in the group, recursively resolve their other services.
            for member in members:
                results.extend(self.resolve_services(member))
        else:
            # Handle the port definitions.
            protocol = item["protocol"].upper()
            port_value = str(item["port"])

            # If it is a port range.
            if "-" in port_value:
                start, end = port_value.split("-")
                # Append the port result
                results.append((protocol, int(start), int(end)))

            # If it is a singular port
            else:
                results.append((protocol, int(port_value), int(port_value)))

        # Return the results
        return results

# ------------ The Engine ----------
class FirewallAnalysisEngine:
    """
    The Firewall Analysis Engine takes the resolver and analyzes the rules
    it checks for shadowing, redundancy, and potential optimizations.
    """

    def __init__(self, policies_csv, addresses_csv, services_csv):
        """
        Initialize the Firewall Analysis Engine object.
        """
        # Load and sanitize policies.
        raw_policies = pd.read_csv(policies_csv)
        self.policies = sanitize_firewall_data(raw_policies)

        # Load and sanitize address objects.
        raw_addr = pd.read_csv(addresses_csv)
        self.addr_datafile = sanitize_firewall_data(raw_addr)
        self.addr_map = self.addr_datafile.set_index('name').to_dict('index')

        # Load and sanitize service objects.
        raw_srv = pd.read_csv(services_csv)
        self.srv_datafile = sanitize_firewall_data(raw_srv)
        self.serv_map =  self.srv_datafile.set_index('name').to_dict('index')

        # Create a new resolver.
        self.resolver = FirewallResolver(self.addr_map, self.serv_map)

    def is_covered(self, rule_a_data, rule_b_data):
        """
        Method that returns True if the items in rule a data intersect with the rule b data.
        Data Format:
        rule_x_data = {
            "src": [list of networks],
            "dst": [list of networks],
            "srv": [list of (proto, start, end)]
        }

        :param rule_a_data: The data of the first rule.
        :param rule_b_data: The data of the second rule.
        :return: True if the rule a data intersects with the rule b data.
        """
        # Iterate over each object in Rule B.
        for src_b in rule_b_data["src"]:
            for dst_b in rule_b_data["dst"]:
                for srv_b in rule_b_data["srv"]:

                    # Initialize a value that will determine if the combination is covered.
                    combination_covered = False

                    # Iterate over each object in Rule A.
                    for src_a in rule_a_data["src"]:
                        for dst_a in rule_a_data["dst"]:
                            for srv_a in rule_a_data["srv"]:

                                # Check the IPs
                                src_match = src_b.subnet_of(src_a)
                                dst_match = dst_b.subnet_of(dst_a)

                                # Check the services (ports)
                                proto_match = (srv_a[0] == 'ANY' or srv_b[0] == srv_a[0])
                                port_match = (srv_b[1] >= srv_a[1] and srv_b[2] <= srv_a[2])

                                # If all of them match then the combination is covered
                                if src_match and dst_match and proto_match and port_match:
                                    combination_covered = True
                                    break
                            if combination_covered: break
                        if combination_covered: break
                    if not combination_covered: return False

        # Return true because they match
        return True

    def run_shadowing_analysis(self):
        """
        Analyzes the policy sets to find any policies that shadow another one or are redundant.

        :return: The list of policies that shadow one another or are redundant.
        """
        # Findings to return.
        findings = []
        # Get the rules that are not disabled.
        df = self.policies[self.policies["status"].str.lower() != "disabled"].reset_index(drop=True)

        # For each rule in the enabled rulesets.
        for i in range(len(df)):
            rule_b = df.iloc[i]

            # Resolve the lower rule
            rule_b_data = {
                "src": self.resolver.resolve_addresses(rule_b["src_addr_name"]),
                "dst": self.resolver.resolve_addresses(rule_b["dst_addr_name"]),
                "srv": self.resolver.resolve_services(rule_b["service"])
            }

            # Get the incoming interface and outgoing interface.
            intf_in_b = set([x.strip() for x in str(rule_b["incoming_intf"]).split(" ")])
            intf_out_b = set([x.strip() for x in str(rule_b["outgoing_intf"]).split(" ")])

            # Iterate over each rule.
            for j in range(i):
                rule_a = df.iloc[j]

                # Get the incoming interface and outgoing interface..
                intf_in_a = set([x.strip() for x in str(rule_a["incoming_intf"]).split(" ")])
                intf_out_a = set([x.strip() for x in str(rule_a["outgoing_intf"]).split(" ")])

                # Check if the interfaces, users, or schedules match.
                intf_in_match = ("any" in intf_in_a or intf_in_b.issubset(intf_in_a))
                intf_out_match = ("any" in intf_out_a or intf_out_b.issubset(intf_out_a))
                user_match = (rule_a["user_group"] == "any" or rule_a["user_group"] == rule_b["user_group"])
                schedule_match = (rule_a["schedule"] == "any" or rule_a["schedule"] == rule_b["schedule"])

                # If both match continue.
                if intf_in_match and intf_out_match and user_match and schedule_match:
                    # Combine the rule a data.
                    rule_a_data = {
                        "src": self.resolver.resolve_addresses(rule_a["src_addr_name"]),
                        "dst": self.resolver.resolve_addresses(rule_a["dst_addr_name"]),
                        "srv": self.resolver.resolve_services(rule_a["service"])
                    }

                    # Now check if the sources, destinations, and services match
                    if self.is_covered(rule_a_data, rule_b_data):
                        # Mark the rule as redundant if the actions match, if they do not match then the rules shadow.
                        issue = "REDUNDANT" if rule_a["action"] == rule_b["action"] else "SHADOWING"

                        # Append the rules to the findings.
                        findings.append({
                            "Policy_ID": rule_b["policy_id"],
                            "Type": issue,
                            "Reason": f"Policy {rule_a["policy_id"]} matches first"
                        })

                        # Break the sub loop.
                        break

        # Return the findings as a pandas dataframe.
        return pd.DataFrame(findings)

    def run_optimization_check(self):
        """
        Finds policies that can be merged into groups.

        :return:
        """
        # Group the policies by src, dst, incoming intf, and action.
        groups = self.policies.groupby(["src_addr_name", "dst_addr_name", "incoming_intf", "action"])
        # Create a list of optimizations
        optimizations = []

        # Iterate over each match and group in the groups.
        for match, group in groups:
            # If the length of the groups is over one, there are matches
            if len(group) > 1:
                # Add as a potential optimization.
                optimizations.append({
                    "Policy_IDs": group["policy_id"].tolist(),
                    "Suggestion": "Consolidate services into a group",
                    "Services": group["service"].tolist()
                })
        # Return the optimizations as a pandas dataframe.
        return pd.DataFrame(optimizations)


def sanitize_firewall_data(datafile):
    """
    Removes any data that could mess up the analysis.

    :param datafile: The datafile to read from.
    :return: The sanitized datafile.
    """

    # Strip whitespace from all string columns.
    datafile = datafile.map(lambda x: x.strip() if isinstance(x, str) else x)

    # Convert empty strings to NaN objects.
    datafile = datafile.replace(r'^\s*$', pd.NA, regex=True)

    # Drop ghost rows.
    datafile = datafile.dropna(how="all")

    # Drop policies with no ID.
    if "policy_id" in datafile:
        datafile = datafile[datafile["policy_id"].notna()]

    # Make sure to fill in any nan strings.
    datafile = datafile.fillna("any").astype(str)

    # Return the sanitized datafile.
    return datafile

# Run the engine.
if __name__ == "__main__":
    # Create a new analyzer engine
    analyzer = FirewallAnalysisEngine("sheets/policies.csv", "sheets/addresses.csv", "sheets/services.csv")
    print(analyzer.run_shadowing_analysis())
    print("\n--- Optimization Opportunities ---")
    print(analyzer.run_optimization_check())
