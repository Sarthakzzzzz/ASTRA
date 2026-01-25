class ScanDecisionAgent:
    """
    AI agent responsible ONLY for deciding next scans.
    No parsing, no execution, no chat.
    """

    def decide_next_scans(self, capabilities, already_run):
        """
        Input: List[CapabilityFact]
        Output: List[str] (scanner names)
        """
        next_scans = set()

        for cap in capabilities:
            if cap.capability == "ssh_auth_surface":
                next_scans.add("ssh_enum")

            if cap.capability == "linux_host":
                next_scans.add("linux_enum")

            if cap.capability == "web_attack_surface":
                next_scans.add("nikto")

        return [s for s in next_scans if s not in already_run]
