import logging
import subprocess

logger = logging.getLogger(__name__)


def validate_chain(chain: str):
    """Validate that the chain name is one of the standard iptables chains."""
    valid_chains = ["INPUT", "OUTPUT", "FORWARD", "PREROUTING", "POSTROUTING"]
    if chain not in valid_chains:
        logger.error("Invalid iptables chain provided.")
        raise ValueError("Invalid chain provided.")


def validate_rule(rule: str):
    """
    Perform basic validation on an iptables rule.
    Since rules can be complex, we mainly want to prevent shell injection.
    """
    # Simple check to prevent multiple commands or pipe
    if any(char in rule for char in [";", "&", "|", ">", "<", "$", "`"]):
        logger.error("Malicious characters detected in iptables rule.")
        raise ValueError("Malicious characters detected in rule.")


def list_rules(chain):
    """
    List iptables rules for a specified chain with line numbers.

    :param chain: The name of the chain (e.g., 'INPUT', 'OUTPUT', 'FORWARD', 'PREROUTING', 'POSTROUTING')
    :return: A list of strings, each representing a rule with its line number
    """

    validate_chain(chain)
    logger.info("Listing iptables rules.")
    # Execute the iptables command with the --line-numbers and --list options
    result = subprocess.run(
        ["iptables", "-L", chain, "--line-numbers"],
        capture_output=True,
        text=True,
        check=True,
    )

    # Split the output into lines
    lines = result.stdout.splitlines()
    # Skip the first two lines (chain name and header)
    rules = lines[2:]
    logger.info("Successfully listed iptables rules.")

    return rules


def apply_rules(chain, line_number, rules):
    """
    Insert multiple iptables rules before a specified line number in the given chain.

    :param chain: The name of the chain (e.g., 'INPUT', 'OUTPUT', 'FORWARD', 'PREROUTING', 'POSTROUTING')
    :param line_number: The line number before which to insert the new rules
    :param rules: A list of iptables rules to insert (e.g., ['-p tcp --dport 80 -j ACCEPT', '-p udp --dport 53 -j ACCEPT'])
    """

    validate_chain(chain)
    # Execute each rule individually without shell=True
    for i, rule in enumerate(rules):
        validate_rule(rule)
        current_line = line_number + i
        # Split the rule into its components.
        # This is a bit tricky as rule might have spaces within arguments.
        # For our usage, rules are usually space-separated flags.
        rule_parts = rule.split()
        cmd = ["iptables", "-I", chain, str(current_line)] + rule_parts

        subprocess.run(cmd, shell=False, check=True)

    logger.info("Successfully inserted %d iptables rules.", len(rules))


def drop_rules(chain, rules):
    """
    Drop multiple iptables rules in the given chain.
    :param chain: The name of the chain (e.g., 'INPUT', 'OUTPUT', 'FORWARD', 'PREROUTING', 'POSTROUTING')
    :param rules: A list of iptables rules to drop (e.g., ['-p tcp --dport 80 -j DROP', '-p udp --dport 53 -j DROP'])
    """

    validate_chain(chain)
    for rule in rules:
        validate_rule(rule)
        rule_parts = rule.split()
        cmd = ["iptables", "-D", chain] + rule_parts

        subprocess.run(cmd, shell=False, check=True)

    logger.info("Successfully dropped %d iptables rules.", len(rules))
