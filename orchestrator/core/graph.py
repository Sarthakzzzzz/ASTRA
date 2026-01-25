import networkx as nx

class AstraGraph:
    def __init__(self):
        self.g = nx.DiGraph()

    def add_asset(self, asset):
        self.g.add_node(asset, type="asset")

    def add_finding(self, finding):
        """
        finding is a StandardFinding object
        Required fields:
            - finding.id
            - finding.target
            - finding.title (or name)
            - finding.severity
        """

        finding_id = finding.id
        asset = finding.target

        # 1️⃣ Ensure asset exists
        self.add_asset(asset)

        # 2️⃣ Add finding node
        if not self.g.has_node(finding_id):
            self.g.add_node(
                finding_id,
                type="finding",
                label=f"Finding: {finding.title}",
                severity=finding.severity,
                tool=finding.source_tool
            )

        # 3️⃣ Asset → Finding edge
        self.g.add_edge(
            asset,
            finding_id,
            relation="exposes"
        )

    def add_technique(self, technique, finding_id):
        self.g.add_node(technique, type="technique")
        self.g.add_edge(finding_id, technique, relation="enables")

    def add_impact(self, impact, technique):
        self.g.add_node(impact, type="impact")
        self.g.add_edge(technique, impact, relation="leads_to")
    
    def get_attack_paths(self):
        """
        Get attack paths from assets to impacts/exploits.
        Only includes "exploit" and higher risk level findings, never raw scan output.
        """
        paths = []
        
        for node in self.g.nodes:
            if self.g.nodes[node].get("type") != "asset":
                continue
                
            # First, try to find complete paths (asset → finding → technique → impact)
            for target in self.g.nodes:
                if self.g.nodes[target].get("type") == "impact":
                    try:
                        for path in nx.all_simple_paths(self.g, node, target):
                            paths.append(path)
                    except nx.NetworkXNoPath:
                        continue
            
            # If no complete impact paths found, include only "exploit" level finding-to-technique paths
            if not paths:
                for target in self.g.nodes:
                    # Only include findings marked as "exploit" or higher
                    if self.g.nodes[target].get("type") == "finding" and self.g.nodes[target].get("risk_level") in ["exploit", "critical"]:
                        try:
                            for path in nx.all_simple_paths(self.g, node, target):
                                paths.append(path)
                        except nx.NetworkXNoPath:
                            continue
        
        return paths
    def add_action(self, action: dict, asset: str):
        """
        Safely add a rule-triggered action to the attack graph.
        Only adds if the action represents an exploitable finding (not enum).
        """

        # 1. Finding - check risk level
        finding_id = action.get("finding_id")
        risk_level = action.get("risk_level", "unknown")
        
        if finding_id:
            self.add_asset(asset)
            if not self.g.has_node(finding_id):
                self.g.add_node(
                    finding_id,
                    type="finding",
                    label=f"Finding: {finding_id}",
                    severity=action.get("severity", "unknown"),
                    risk_level=risk_level,
                    tool=action.get("tool", "unknown")
                )
            self.g.add_edge(asset, finding_id, relation="exposes")
        else:
            # No finding → cannot build a chain
            return

        # 2. Technique (optional but recommended)
        technique = action.get("technique")
        if technique:
            if not self.g.has_node(technique):
                self.add_technique(technique, finding_id)
            else:
                # Node already exists, just add edge if it doesn't
                if not self.g.has_edge(finding_id, technique):
                    self.g.add_edge(finding_id, technique, relation="enables")

        # 3. Impact (only if technique exists)
        impact = action.get("impact")
        if technique and impact:
            if not self.g.has_node(impact):
                self.add_impact(impact, technique)
            else:
                # Node already exists, just add edge if it doesn't
                if not self.g.has_edge(technique, impact):
                    self.g.add_edge(technique, impact, relation="leads_to")

