"""
report_fixes.py - helpers for the DCSRE forensic report generator.
Put this file next to your report generator module and import from it.
"""
import html
import ipaddress
import re
from datetime import datetime
from typing import Any, Dict, Iterable, List, Optional, Set
from .entity_classification import is_internal_ip

# ---------------------------------------------------------------------------
# 1. Tactic is derived from the technique ID, never trusted from rule defaults.
#    Source: MITRE ATT&CK Enterprise v15 (2024).
#    The rule's own mitre_tactic is used as a fallback; if both are missing
#    the tactic is shown as "Unknown" and a warning is added to the report.
# ---------------------------------------------------------------------------
TACTIC_BY_TECHNIQUE: Dict[str, str] = {
    # ── Reconnaissance ────────────────────────────────────────────────────
    "T1595": "Reconnaissance", "T1595.001": "Reconnaissance",
    "T1595.002": "Reconnaissance", "T1595.003": "Reconnaissance",
    "T1592": "Reconnaissance", "T1592.001": "Reconnaissance",
    "T1592.002": "Reconnaissance", "T1592.003": "Reconnaissance",
    "T1592.004": "Reconnaissance",
    "T1589": "Reconnaissance", "T1589.001": "Reconnaissance",
    "T1589.002": "Reconnaissance", "T1589.003": "Reconnaissance",
    "T1590": "Reconnaissance", "T1590.001": "Reconnaissance",
    "T1590.002": "Reconnaissance", "T1590.003": "Reconnaissance",
    "T1590.004": "Reconnaissance", "T1590.005": "Reconnaissance",
    "T1590.006": "Reconnaissance",
    "T1591": "Reconnaissance", "T1591.001": "Reconnaissance",
    "T1591.002": "Reconnaissance", "T1591.003": "Reconnaissance",
    "T1591.004": "Reconnaissance",
    "T1598": "Reconnaissance", "T1598.001": "Reconnaissance",
    "T1598.002": "Reconnaissance", "T1598.003": "Reconnaissance",
    "T1597": "Reconnaissance", "T1597.001": "Reconnaissance",
    "T1597.002": "Reconnaissance",
    "T1596": "Reconnaissance", "T1596.001": "Reconnaissance",
    "T1596.002": "Reconnaissance", "T1596.003": "Reconnaissance",
    "T1596.004": "Reconnaissance", "T1596.005": "Reconnaissance",
    "T1593": "Reconnaissance", "T1593.001": "Reconnaissance",
    "T1593.002": "Reconnaissance", "T1593.003": "Reconnaissance",
    "T1594": "Reconnaissance",
    # ── Resource Development ─────────────────────────────────────────
    "T1583": "Resource Development", "T1583.001": "Resource Development",
    "T1583.002": "Resource Development", "T1583.003": "Resource Development",
    "T1583.004": "Resource Development", "T1583.005": "Resource Development",
    "T1583.006": "Resource Development", "T1583.007": "Resource Development",
    "T1583.008": "Resource Development",
    "T1586": "Resource Development", "T1586.001": "Resource Development",
    "T1586.002": "Resource Development", "T1586.003": "Resource Development",
    "T1584": "Resource Development", "T1584.001": "Resource Development",
    "T1584.002": "Resource Development", "T1584.003": "Resource Development",
    "T1584.004": "Resource Development", "T1584.005": "Resource Development",
    "T1584.006": "Resource Development", "T1584.007": "Resource Development",
    "T1587": "Resource Development", "T1587.001": "Resource Development",
    "T1587.002": "Resource Development", "T1587.003": "Resource Development",
    "T1587.004": "Resource Development",
    "T1585": "Resource Development", "T1585.001": "Resource Development",
    "T1585.002": "Resource Development", "T1585.003": "Resource Development",
    "T1588": "Resource Development", "T1588.001": "Resource Development",
    "T1588.002": "Resource Development", "T1588.003": "Resource Development",
    "T1588.004": "Resource Development", "T1588.005": "Resource Development",
    "T1588.006": "Resource Development", "T1588.007": "Resource Development",
    "T1608": "Resource Development", "T1608.001": "Resource Development",
    "T1608.002": "Resource Development", "T1608.003": "Resource Development",
    "T1608.004": "Resource Development", "T1608.005": "Resource Development",
    "T1608.006": "Resource Development",
    # ── Initial Access ──────────────────────────────────────────────────
    "T1189": "Initial Access", "T1190": "Initial Access",
    "T1133": "Initial Access", "T1200": "Initial Access",
    "T1566": "Initial Access", "T1566.001": "Initial Access",
    "T1566.002": "Initial Access", "T1566.003": "Initial Access",
    "T1566.004": "Initial Access",
    "T1091": "Initial Access",
    "T1195": "Initial Access", "T1195.001": "Initial Access",
    "T1195.002": "Initial Access", "T1195.003": "Initial Access",
    "T1199": "Initial Access",
    "T1078": "Initial Access", "T1078.001": "Initial Access",
    "T1078.002": "Initial Access", "T1078.003": "Initial Access",
    "T1078.004": "Initial Access",
    "T1659": "Initial Access",
    # ── Execution ─────────────────────────────────────────────────────────
    "T1059": "Execution", "T1059.001": "Execution", "T1059.002": "Execution",
    "T1059.003": "Execution", "T1059.004": "Execution", "T1059.005": "Execution",
    "T1059.006": "Execution", "T1059.007": "Execution", "T1059.008": "Execution",
    "T1059.009": "Execution", "T1059.010": "Execution",
    "T1609": "Execution", "T1610": "Execution",
    "T1203": "Execution",
    "T1559": "Execution", "T1559.001": "Execution", "T1559.002": "Execution",
    "T1559.003": "Execution",
    "T1106": "Execution",
    "T1053": "Execution", "T1053.002": "Execution", "T1053.003": "Execution",
    "T1053.004": "Execution", "T1053.005": "Execution", "T1053.006": "Execution",
    "T1053.007": "Execution",
    "T1129": "Execution", "T1072": "Execution",
    "T1569": "Execution", "T1569.001": "Execution", "T1569.002": "Execution",
    "T1204": "Execution", "T1204.001": "Execution", "T1204.002": "Execution",
    "T1204.003": "Execution",
    "T1047": "Execution",
    # ── Persistence ──────────────────────────────────────────────────────
    "T1098": "Persistence", "T1098.001": "Persistence", "T1098.002": "Persistence",
    "T1098.003": "Persistence", "T1098.004": "Persistence", "T1098.005": "Persistence",
    "T1098.006": "Persistence",
    "T1197": "Persistence",
    "T1547": "Persistence", "T1547.001": "Persistence", "T1547.002": "Persistence",
    "T1547.003": "Persistence", "T1547.004": "Persistence", "T1547.005": "Persistence",
    "T1547.006": "Persistence", "T1547.007": "Persistence", "T1547.008": "Persistence",
    "T1547.009": "Persistence", "T1547.010": "Persistence", "T1547.011": "Persistence",
    "T1547.012": "Persistence", "T1547.013": "Persistence", "T1547.014": "Persistence",
    "T1547.015": "Persistence",
    "T1037": "Persistence", "T1037.001": "Persistence", "T1037.002": "Persistence",
    "T1037.003": "Persistence", "T1037.004": "Persistence", "T1037.005": "Persistence",
    "T1176": "Persistence", "T1554": "Persistence",
    "T1136": "Persistence", "T1136.001": "Persistence", "T1136.002": "Persistence",
    "T1136.003": "Persistence",
    "T1543": "Persistence", "T1543.001": "Persistence", "T1543.002": "Persistence",
    "T1543.003": "Persistence", "T1543.004": "Persistence",
    "T1546": "Persistence", "T1546.001": "Persistence", "T1546.002": "Persistence",
    "T1546.003": "Persistence", "T1546.004": "Persistence", "T1546.005": "Persistence",
    "T1546.006": "Persistence", "T1546.007": "Persistence", "T1546.008": "Persistence",
    "T1546.009": "Persistence", "T1546.010": "Persistence", "T1546.011": "Persistence",
    "T1546.012": "Persistence", "T1546.013": "Persistence", "T1546.014": "Persistence",
    "T1546.015": "Persistence", "T1546.016": "Persistence",
    "T1525": "Persistence",
    "T1556": "Persistence", "T1556.001": "Persistence", "T1556.002": "Persistence",
    "T1556.003": "Persistence", "T1556.004": "Persistence", "T1556.005": "Persistence",
    "T1556.006": "Persistence", "T1556.007": "Persistence", "T1556.008": "Persistence",
    "T1137": "Persistence", "T1137.001": "Persistence", "T1137.002": "Persistence",
    "T1137.003": "Persistence", "T1137.004": "Persistence", "T1137.005": "Persistence",
    "T1137.006": "Persistence",
    "T1205": "Persistence", "T1205.001": "Persistence", "T1205.002": "Persistence",
    "T1505": "Persistence", "T1505.001": "Persistence", "T1505.002": "Persistence",
    "T1505.003": "Persistence", "T1505.004": "Persistence", "T1505.005": "Persistence",
    "T1542": "Persistence", "T1542.001": "Persistence", "T1542.002": "Persistence",
    "T1542.003": "Persistence", "T1542.004": "Persistence", "T1542.005": "Persistence",
    "T1601": "Persistence", "T1601.001": "Persistence", "T1601.002": "Persistence",
    # ── Privilege Escalation ───────────────────────────────────────────
    "T1548": "Privilege Escalation", "T1548.001": "Privilege Escalation",
    "T1548.002": "Privilege Escalation", "T1548.003": "Privilege Escalation",
    "T1548.004": "Privilege Escalation", "T1548.005": "Privilege Escalation",
    "T1548.006": "Privilege Escalation",
    "T1134": "Privilege Escalation", "T1134.001": "Privilege Escalation",
    "T1134.002": "Privilege Escalation", "T1134.003": "Privilege Escalation",
    "T1134.004": "Privilege Escalation", "T1134.005": "Privilege Escalation",
    "T1134.006": "Privilege Escalation",
    "T1484": "Privilege Escalation", "T1484.001": "Privilege Escalation",
    "T1484.002": "Privilege Escalation",
    "T1611": "Privilege Escalation",
    "T1068": "Privilege Escalation",
    "T1055": "Privilege Escalation", "T1055.001": "Privilege Escalation",
    "T1055.002": "Privilege Escalation", "T1055.003": "Privilege Escalation",
    "T1055.004": "Privilege Escalation", "T1055.005": "Privilege Escalation",
    "T1055.008": "Privilege Escalation", "T1055.009": "Privilege Escalation",
    "T1055.011": "Privilege Escalation", "T1055.012": "Privilege Escalation",
    "T1055.013": "Privilege Escalation", "T1055.014": "Privilege Escalation",
    "T1055.015": "Privilege Escalation",
    # ── Defense Evasion ────────────────────────────────────────────────
    "T1622": "Defense Evasion", "T1140": "Defense Evasion",
    "T1006": "Defense Evasion",
    "T1480": "Defense Evasion", "T1480.001": "Defense Evasion",
    "T1211": "Defense Evasion",
    "T1222": "Defense Evasion", "T1222.001": "Defense Evasion",
    "T1222.002": "Defense Evasion",
    "T1564": "Defense Evasion", "T1564.001": "Defense Evasion",
    "T1564.002": "Defense Evasion", "T1564.003": "Defense Evasion",
    "T1564.004": "Defense Evasion", "T1564.005": "Defense Evasion",
    "T1564.006": "Defense Evasion", "T1564.007": "Defense Evasion",
    "T1564.008": "Defense Evasion", "T1564.009": "Defense Evasion",
    "T1564.010": "Defense Evasion", "T1564.011": "Defense Evasion",
    "T1574": "Defense Evasion", "T1574.001": "Defense Evasion",
    "T1574.002": "Defense Evasion", "T1574.004": "Defense Evasion",
    "T1574.005": "Defense Evasion", "T1574.006": "Defense Evasion",
    "T1574.007": "Defense Evasion", "T1574.008": "Defense Evasion",
    "T1574.009": "Defense Evasion", "T1574.010": "Defense Evasion",
    "T1574.011": "Defense Evasion", "T1574.012": "Defense Evasion",
    "T1574.013": "Defense Evasion",
    "T1562": "Defense Evasion", "T1562.001": "Defense Evasion",
    "T1562.002": "Defense Evasion", "T1562.003": "Defense Evasion",
    "T1562.004": "Defense Evasion", "T1562.006": "Defense Evasion",
    "T1562.007": "Defense Evasion", "T1562.008": "Defense Evasion",
    "T1562.009": "Defense Evasion", "T1562.010": "Defense Evasion",
    "T1562.011": "Defense Evasion", "T1562.012": "Defense Evasion",
    "T1070": "Defense Evasion", "T1070.001": "Defense Evasion",
    "T1070.002": "Defense Evasion", "T1070.003": "Defense Evasion",
    "T1070.004": "Defense Evasion", "T1070.005": "Defense Evasion",
    "T1070.006": "Defense Evasion", "T1070.007": "Defense Evasion",
    "T1070.008": "Defense Evasion", "T1070.009": "Defense Evasion",
    "T1202": "Defense Evasion",
    "T1036": "Defense Evasion", "T1036.001": "Defense Evasion",
    "T1036.002": "Defense Evasion", "T1036.003": "Defense Evasion",
    "T1036.004": "Defense Evasion", "T1036.005": "Defense Evasion",
    "T1036.006": "Defense Evasion", "T1036.007": "Defense Evasion",
    "T1036.008": "Defense Evasion", "T1036.009": "Defense Evasion",
    "T1578": "Defense Evasion", "T1578.001": "Defense Evasion",
    "T1578.002": "Defense Evasion", "T1578.003": "Defense Evasion",
    "T1578.004": "Defense Evasion",
    "T1112": "Defense Evasion",
    "T1599": "Defense Evasion", "T1599.001": "Defense Evasion",
    "T1027": "Defense Evasion", "T1027.001": "Defense Evasion",
    "T1027.002": "Defense Evasion", "T1027.003": "Defense Evasion",
    "T1027.004": "Defense Evasion", "T1027.005": "Defense Evasion",
    "T1027.006": "Defense Evasion", "T1027.007": "Defense Evasion",
    "T1027.008": "Defense Evasion", "T1027.009": "Defense Evasion",
    "T1027.010": "Defense Evasion", "T1027.011": "Defense Evasion",
    "T1027.012": "Defense Evasion", "T1027.013": "Defense Evasion",
    "T1207": "Defense Evasion", "T1014": "Defense Evasion",
    "T1218": "Defense Evasion", "T1218.001": "Defense Evasion",
    "T1218.002": "Defense Evasion", "T1218.003": "Defense Evasion",
    "T1218.004": "Defense Evasion", "T1218.005": "Defense Evasion",
    "T1218.007": "Defense Evasion", "T1218.008": "Defense Evasion",
    "T1218.009": "Defense Evasion", "T1218.010": "Defense Evasion",
    "T1218.011": "Defense Evasion", "T1218.012": "Defense Evasion",
    "T1218.013": "Defense Evasion", "T1218.014": "Defense Evasion",
    "T1216": "Defense Evasion", "T1216.001": "Defense Evasion",
    "T1216.002": "Defense Evasion",
    "T1553": "Defense Evasion", "T1553.001": "Defense Evasion",
    "T1553.002": "Defense Evasion", "T1553.003": "Defense Evasion",
    "T1553.004": "Defense Evasion", "T1553.005": "Defense Evasion",
    "T1553.006": "Defense Evasion",
    "T1221": "Defense Evasion",
    "T1127": "Defense Evasion", "T1127.001": "Defense Evasion",
    "T1535": "Defense Evasion",
    "T1550": "Defense Evasion", "T1550.001": "Defense Evasion",
    "T1550.002": "Defense Evasion", "T1550.003": "Defense Evasion",
    "T1550.004": "Defense Evasion",
    "T1497": "Defense Evasion", "T1497.001": "Defense Evasion",
    "T1497.002": "Defense Evasion", "T1497.003": "Defense Evasion",
    "T1600": "Defense Evasion", "T1600.001": "Defense Evasion",
    "T1600.002": "Defense Evasion",
    "T1220": "Defense Evasion",
    # ── Credential Access ───────────────────────────────────────────────
    "T1110": "Credential Access", "T1110.001": "Credential Access",
    "T1110.002": "Credential Access", "T1110.003": "Credential Access",
    "T1110.004": "Credential Access",
    "T1555": "Credential Access", "T1555.001": "Credential Access",
    "T1555.002": "Credential Access", "T1555.003": "Credential Access",
    "T1555.004": "Credential Access", "T1555.005": "Credential Access",
    "T1555.006": "Credential Access",
    "T1212": "Credential Access", "T1187": "Credential Access",
    "T1606": "Credential Access", "T1606.001": "Credential Access",
    "T1606.002": "Credential Access",
    "T1056": "Credential Access", "T1056.001": "Credential Access",
    "T1056.002": "Credential Access", "T1056.003": "Credential Access",
    "T1056.004": "Credential Access",
    "T1557": "Credential Access", "T1557.001": "Credential Access",
    "T1557.002": "Credential Access", "T1557.003": "Credential Access",
    "T1111": "Credential Access", "T1621": "Credential Access",
    "T1040": "Credential Access",
    "T1003": "Credential Access", "T1003.001": "Credential Access",
    "T1003.002": "Credential Access", "T1003.003": "Credential Access",
    "T1003.004": "Credential Access", "T1003.005": "Credential Access",
    "T1003.006": "Credential Access", "T1003.007": "Credential Access",
    "T1003.008": "Credential Access",
    "T1528": "Credential Access", "T1649": "Credential Access",
    "T1558": "Credential Access", "T1558.001": "Credential Access",
    "T1558.002": "Credential Access", "T1558.003": "Credential Access",
    "T1558.004": "Credential Access",
    "T1539": "Credential Access",
    "T1552": "Credential Access", "T1552.001": "Credential Access",
    "T1552.002": "Credential Access", "T1552.003": "Credential Access",
    "T1552.004": "Credential Access", "T1552.005": "Credential Access",
    "T1552.006": "Credential Access", "T1552.007": "Credential Access",
    "T1552.008": "Credential Access",
    # ── Discovery ─────────────────────────────────────────────────────────
    "T1087": "Discovery", "T1087.001": "Discovery", "T1087.002": "Discovery",
    "T1087.003": "Discovery", "T1087.004": "Discovery",
    "T1010": "Discovery", "T1217": "Discovery", "T1580": "Discovery",
    "T1538": "Discovery", "T1526": "Discovery", "T1619": "Discovery",
    "T1482": "Discovery", "T1083": "Discovery", "T1615": "Discovery",
    "T1046": "Discovery", "T1135": "Discovery", "T1201": "Discovery",
    "T1120": "Discovery",
    "T1069": "Discovery", "T1069.001": "Discovery", "T1069.002": "Discovery",
    "T1069.003": "Discovery",
    "T1057": "Discovery", "T1012": "Discovery", "T1018": "Discovery",
    "T1518": "Discovery", "T1518.001": "Discovery",
    "T1082": "Discovery",
    "T1614": "Discovery", "T1614.001": "Discovery",
    "T1016": "Discovery", "T1016.001": "Discovery", "T1016.002": "Discovery",
    "T1049": "Discovery", "T1033": "Discovery", "T1007": "Discovery",
    "T1124": "Discovery",
    # ── Lateral Movement ────────────────────────────────────────────────
    "T1210": "Lateral Movement", "T1534": "Lateral Movement",
    "T1570": "Lateral Movement",
    "T1563": "Lateral Movement", "T1563.001": "Lateral Movement",
    "T1563.002": "Lateral Movement",
    "T1021": "Lateral Movement", "T1021.001": "Lateral Movement",
    "T1021.002": "Lateral Movement", "T1021.003": "Lateral Movement",
    "T1021.004": "Lateral Movement", "T1021.005": "Lateral Movement",
    "T1021.006": "Lateral Movement", "T1021.007": "Lateral Movement",
    "T1021.008": "Lateral Movement",
    "T1080": "Lateral Movement",
    # ── Collection ──────────────────────────────────────────────────────
    "T1560": "Collection", "T1560.001": "Collection", "T1560.002": "Collection",
    "T1560.003": "Collection",
    "T1123": "Collection", "T1119": "Collection", "T1115": "Collection",
    "T1530": "Collection",
    "T1602": "Collection", "T1602.001": "Collection", "T1602.002": "Collection",
    "T1213": "Collection", "T1213.001": "Collection", "T1213.002": "Collection",
    "T1213.003": "Collection",
    "T1005": "Collection", "T1039": "Collection", "T1025": "Collection",
    "T1074": "Collection", "T1074.001": "Collection", "T1074.002": "Collection",
    "T1114": "Collection", "T1114.001": "Collection", "T1114.002": "Collection",
    "T1114.003": "Collection",
    "T1185": "Collection", "T1113": "Collection",
    # ── Command and Control ───────────────────────────────────────────
    "T1071": "Command and Control", "T1071.001": "Command and Control",
    "T1071.002": "Command and Control", "T1071.003": "Command and Control",
    "T1071.004": "Command and Control",
    "T1092": "Command and Control",
    "T1132": "Command and Control", "T1132.001": "Command and Control",
    "T1132.002": "Command and Control",
    "T1001": "Command and Control", "T1001.001": "Command and Control",
    "T1001.002": "Command and Control", "T1001.003": "Command and Control",
    "T1568": "Command and Control", "T1568.001": "Command and Control",
    "T1568.002": "Command and Control", "T1568.003": "Command and Control",
    "T1573": "Command and Control", "T1573.001": "Command and Control",
    "T1573.002": "Command and Control",
    "T1008": "Command and Control", "T1105": "Command and Control",
    "T1104": "Command and Control", "T1095": "Command and Control",
    "T1571": "Command and Control", "T1572": "Command and Control",
    "T1090": "Command and Control", "T1090.001": "Command and Control",
    "T1090.002": "Command and Control", "T1090.003": "Command and Control",
    "T1090.004": "Command and Control",
    "T1219": "Command and Control", "T1219.001": "Command and Control",
    "T1219.002": "Command and Control",
    "T1102": "Command and Control", "T1102.001": "Command and Control",
    "T1102.002": "Command and Control", "T1102.003": "Command and Control",
    # ── Exfiltration ─────────────────────────────────────────────────────
    "T1020": "Exfiltration", "T1020.001": "Exfiltration",
    "T1030": "Exfiltration",
    "T1048": "Exfiltration", "T1048.001": "Exfiltration",
    "T1048.002": "Exfiltration", "T1048.003": "Exfiltration",
    "T1041": "Exfiltration",
    "T1011": "Exfiltration", "T1011.001": "Exfiltration",
    "T1052": "Exfiltration", "T1052.001": "Exfiltration",
    "T1567": "Exfiltration", "T1567.001": "Exfiltration",
    "T1567.002": "Exfiltration", "T1567.003": "Exfiltration",
    "T1567.004": "Exfiltration",
    "T1029": "Exfiltration", "T1537": "Exfiltration",
    # ── Impact ────────────────────────────────────────────────────────────
    "T1531": "Impact", "T1485": "Impact", "T1486": "Impact",
    "T1491": "Impact", "T1491.001": "Impact", "T1491.002": "Impact",
    "T1499": "Impact", "T1499.001": "Impact", "T1499.002": "Impact",
    "T1499.003": "Impact", "T1499.004": "Impact",
    "T1657": "Impact", "T1495": "Impact", "T1490": "Impact",
    "T1498": "Impact", "T1498.001": "Impact", "T1498.002": "Impact",
    "T1496": "Impact", "T1489": "Impact", "T1529": "Impact",
    "T1565": "Impact", "T1565.001": "Impact", "T1565.002": "Impact",
    "T1565.003": "Impact",
}

TACTIC_ORDER = [
    "Reconnaissance", "Resource Development",
    "Initial Access", "Execution", "Persistence", "Privilege Escalation",
    "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement",
    "Collection", "Command and Control", "Exfiltration", "Impact",
]


def tactic_for(technique: Optional[str], fallback: str = "Unknown") -> str:
    """Return the canonical tactic for a MITRE technique ID.

    Resolution order:
      1. TACTIC_BY_TECHNIQUE lookup (sub-technique, then parent)
      2. *fallback* (usually the rule's own mitre_tactic field)
      3. "Unknown"
    """
    if not technique:
        return fallback or "Unknown"
    t = str(technique).strip().upper()
    result = TACTIC_BY_TECHNIQUE.get(t) or TACTIC_BY_TECHNIQUE.get(t.split(".")[0])
    return result if result else (fallback or "Unknown")


def tactic_for_tracked(
    technique: Optional[str],
    fallback: str = "Unknown",
    warnings: Optional[List[str]] = None,
) -> str:
    """Same as tactic_for but appends a warning to *warnings* when the technique
    is not found in TACTIC_BY_TECHNIQUE so the report's Limitations section can
    flag it."""
    if not technique:
        return fallback or "Unknown"
    t = str(technique).strip().upper()
    result = TACTIC_BY_TECHNIQUE.get(t) or TACTIC_BY_TECHNIQUE.get(t.split(".")[0])
    if result:
        return result
    used = fallback or "Unknown"
    if warnings is not None:
        warnings.append(
            f"Technique {t} is not in the ATT&CK lookup table; "
            f"tactic shown as '{used}' from rule definition."
        )
    return used


# ---------------------------------------------------------------------------
# 2. Canonical rule names (merges variants, prettifies snake_case ids)
# ---------------------------------------------------------------------------
ALIASES = {
    "security audit log cleared": "Security Event Log Cleared",
    "inhibit system recovery via shadow copy deletion": "Shadow Copy Deletion",
    "large outbound transfer or rclone staging": "Large Outbound Transfer via rclone",
    "remote service creation via psexec or service control": "Remote Service Creation (PsExec)",
    "active directory database extraction via ntdsutil": "NTDS.dit Extraction via ntdsutil",
    "lsass memory access and credential dumping": "LSASS Memory Access via comsvcs.dll",
    "ssh_bruteforce": "SSH Brute Force",
    "data_exfiltration": "Data Exfiltration Over C2 Channel",
}


def canonical_title(raw: Any) -> str:
    s = str(raw or "").strip()
    if s.lower() in ALIASES:
        return ALIASES[s.lower()]
    if "_" in s and " " not in s:
        return " ".join(w.capitalize() for w in s.split("_"))
    return s


# ---------------------------------------------------------------------------
# 3. Merge duplicate detections (keeps the same dict shape the renderers use)
# ---------------------------------------------------------------------------
SEV_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}


def _sev(d: Dict[str, Any]) -> str:
    return str(d.get("severity", "")).lower()


def dedupe_detections(
    detections: List[Dict[str, Any]],
    warnings: Optional[List[str]] = None,
) -> List[Dict[str, Any]]:
    """Merge detections that share the same canonical title.  Keeps the highest
    severity.  Passes *warnings* through to tactic_for_tracked so that unknown
    techniques are recorded in the report's Limitations section."""
    merged: Dict[str, Dict[str, Any]] = {}
    for d in detections:
        title = canonical_title(d.get("rule_name") or d.get("rule_id"))
        m = merged.get(title.lower())
        if m is None:
            m = dict(d)
            m["rule_name"] = title
            m["severity"] = _sev(d)
            # Seed from the pre-built mitre_techniques_all list if present
            seed = d.get("mitre_techniques_all") or []
            m["mitre_techniques_all"] = list(seed)
            m["merged_ids"] = []
            merged[title.lower()] = m
        for event_id in d.get("matching_event_ids") or []:
            if event_id:
                ids = m.setdefault("matching_event_ids", [])
                if str(event_id) not in {str(existing) for existing in ids}:
                    ids.append(str(event_id))
        for field in ("source_files", "sources", "source_record_references"):
            values = d.get(field) or []
            if not isinstance(values, (list, tuple, set)):
                values = [values]
            merged_values = m.get(field)
            if not isinstance(merged_values, list):
                merged_values = [merged_values] if merged_values else []
                m[field] = merged_values
            for value in values:
                if value and value not in merged_values:
                    merged_values.append(value)
        # Add individual technique if not already present
        for tech in (d.get("mitre_techniques_all") or [d.get("mitre_technique")]):
            if tech and tech not in m["mitre_techniques_all"]:
                m["mitre_techniques_all"].append(tech)
        if d.get("id") and d["id"] not in m["merged_ids"]:
            m["merged_ids"].append(d["id"])
        if SEV_RANK.get(_sev(d), 0) > SEV_RANK.get(m["severity"], 0):
            m["severity"] = _sev(d)
        fs, ls = d.get("first_seen"), d.get("last_seen")
        if fs and (not m.get("first_seen") or str(fs) < str(m["first_seen"])):
            m["first_seen"] = fs
        if ls and (not m.get("last_seen") or str(ls) > str(m["last_seen"])):
            m["last_seen"] = ls
    out = list(merged.values())
    for m in out:
        primary = (
            m["mitre_techniques_all"][0]
            if m["mitre_techniques_all"]
            else m.get("mitre_technique")
        )
        m["mitre_technique"] = primary
        m["mitre_tactic"] = tactic_for_tracked(
            primary,
            fallback=m.get("mitre_tactic", "Unknown"),
            warnings=warnings,
        )
    return sorted(out, key=lambda x: str(x.get("first_seen", "")))


# ---------------------------------------------------------------------------
# 4. Users and hosts
# ---------------------------------------------------------------------------
def norm_user(u: Any) -> Optional[str]:
    if not u:
        return None
    s = re.sub(r"^user:\s*", "", str(u).strip(), flags=re.I)
    if "\\" in s:
        domain, username = s.split("\\", 1)
    elif "@" in s:
        username, domain = s.split("@", 1)
        domain = domain.split(".")[0]
    else:
        domain, username = "", s
    domain, username = domain.strip().lower(), username.strip().lower()
    return None if username in ("", "unknown", "system", "-", "n/a") else username


def format_user(u: Any) -> str:
    """Render an account as DOMAIN\\user, preserving an observed domain."""
    raw = re.sub(r"^user:\s*", "", str(u or "").strip(), flags=re.I)
    if not raw or raw.lower() in ("unknown", "system", "-", "n/a"):
        return raw or "unknown"
    if "\\" in raw:
        domain, username = raw.split("\\", 1)
    elif "@" in raw:
        username, domain = raw.split("@", 1)
        domain = domain.split(".")[0]
    else:
        domain, username = "", raw
    return f"{domain.strip().upper()}\\{username.strip()}" if domain.strip() else username.strip()


def unique_users(users: Iterable[Any]) -> List[str]:
    candidates: List[tuple[str, str, str]] = []
    for u in users:
        key = norm_user(u)
        if not key:
            continue
        raw = re.sub(r"^user:\s*", "", str(u).strip(), flags=re.I)
        if "\\" in raw:
            domain, username = raw.split("\\", 1)
        elif "@" in raw:
            username, domain = raw.split("@", 1)
            domain = domain.split(".")[0]
        else:
            domain, username = "", raw
        candidates.append((key, domain.upper(), username))
    concrete_domains: Dict[str, set] = {}
    for _, domain, username in candidates:
        if domain:
            concrete_domains.setdefault(username.lower(), set()).add(domain)
    best: Dict[str, str] = {}
    for key, domain, username in candidates:
        # DOMAIN is our placeholder when the source supplied no domain. Prefer
        # a concrete domain for that same username when matching evidence has one.
        if not domain and concrete_domains.get(username.lower()):
            continue
        if key not in best or ("\\" not in best[key] and domain):
            best[key] = f"{domain}\\{username}" if domain else username
    return sorted(best.values(), key=str.lower)


def _is_private(ip: str) -> bool:
    return is_internal_ip(ip)


def build_ip_host_map(events: List[Dict[str, Any]]) -> Dict[str, str]:
    """Map internal IP -> hostname, only when an IP maps to exactly one host.
    Review the result: events logged BY a server ABOUT another machine's IP
    can create wrong pairs (those get dropped when the IP maps to 2+ hosts)."""
    seen: Dict[str, set] = {}
    for ev in events:
        host = ev.get("host")
        if not host or str(host).startswith("unknown"):
            continue
        for ip in (ev.get("src_ip"), ev.get("dst_ip")):
            if ip and _is_private(ip):
                seen.setdefault(str(ip), set()).add(str(host))
    return {ip: next(iter(h)) for ip, h in seen.items() if len(h) == 1}


def resolve_hosts(hosts: Iterable[str], ip_map: Dict[str, str]) -> List[str]:
    return sorted({ip_map.get(h, h) for h in hosts})


# ---------------------------------------------------------------------------
# 5. Timeline: merge repeated source records, fill unknown hosts, no row limit
# ---------------------------------------------------------------------------
def merge_timeline(events: List[Dict[str, Any]], ip_map: Optional[Dict[str, str]] = None,
                   max_rows: Optional[int] = None) -> List[Dict[str, Any]]:
    ip_map = ip_map or {}
    known_user_candidates: Dict[tuple, set] = {}
    for ev in events:
        timestamp = str(ev.get("timestamp", ""))[:19]
        host = ip_map.get(ev.get("host"), ev.get("host", ""))
        user = ev.get("user")
        if timestamp and host and user and not str(user).lower().startswith("unknown"):
            if str(user).upper() not in ("SYSTEM", "-"):
                known_user_candidates.setdefault((timestamp, str(host)), set()).add(format_user(user))
    # Fill unknown users only when exactly one account is present on that host
    # and second; do not guess when events disagree.
    known_users = {}
    for key, users in known_user_candidates.items():
        concrete = {user for user in users if not user.upper().startswith("DOMAIN\\")}
        candidates = concrete or users
        if len(candidates) == 1:
            known_users[key] = next(iter(candidates))

    merged: Dict[tuple, Dict[str, Any]] = {}
    for ev in events:
        e = dict(ev)
        host = e.get("host")
        if host in ip_map:
            e["host"] = ip_map[host]
        elif (not host or str(host).startswith("unknown")) and e.get("src_ip") in ip_map:
            e["host"] = ip_map[e["src_ip"]]
        timestamp = str(e.get("timestamp", ""))[:19]
        if (
            (not e.get("user") or str(e.get("user")).lower().startswith("unknown"))
            and (timestamp, str(e.get("host", ""))) in known_users
        ):
            e["user"] = known_users[(timestamp, str(e.get("host", "")))]
        elif e.get("user"):
            formatted = format_user(e["user"])
            known = known_users.get((timestamp, str(e.get("host", ""))))
            if (
                formatted.upper().startswith("DOMAIN\\")
                and known
                and known.split("\\", 1)[-1].casefold() == formatted.split("\\", 1)[-1].casefold()
            ):
                formatted = known
            e["user"] = formatted
        src = str(e.get("source_file") or e.get("source") or "")
        host_key = str(e.get("host", ""))
        action_key = re.sub(r"[^a-z0-9]+", " ", str(e.get("action", "")).lower()).strip()
        key = (timestamp, host_key, action_key)
        if key not in merged and action_key:
            try:
                current_time = datetime.fromisoformat(str(e.get("timestamp", "")).replace("Z", "+00:00"))
            except ValueError:
                current_time = None
            if current_time:
                for candidate_key, candidate in merged.items():
                    if candidate_key[1] != host_key or candidate_key[2] != action_key:
                        continue
                    try:
                        previous_time = datetime.fromisoformat(str(candidate.get("timestamp", "")).replace("Z", "+00:00"))
                    except ValueError:
                        continue
                    if previous_time.tzinfo is None and current_time.tzinfo is not None:
                        previous_time = previous_time.replace(tzinfo=current_time.tzinfo)
                    if current_time.tzinfo is None and previous_time.tzinfo is not None:
                        current_time = current_time.replace(tzinfo=previous_time.tzinfo)
                    if abs((current_time - previous_time).total_seconds()) <= 60:
                        key = candidate_key
                        break
        if key in merged:
            m = merged[key]
            if src and src not in m["corroborated_by"]:
                m["corroborated_by"].append(src)
            if (
                (not m.get("user") or str(m.get("user")).lower().startswith("unknown"))
                and e.get("user")
            ):
                m["user"] = e["user"]
            if SEV_RANK.get(_sev(e), 0) > SEV_RANK.get(_sev(m), 0):
                m["severity"] = e.get("severity")
            for field in ("source_record_references",):
                refs = list(m.get(field) or [])
                refs.extend(e.get(field) or [])
                m[field] = sorted(set(refs))
            for field in ("mitre_tactic", "mitre_technique"):
                values = {part.strip() for item in (m.get(field), e.get(field)) if item for part in str(item).split(",") if part.strip()}
                m[field] = ", ".join(sorted(values))
        else:
            e["corroborated_by"] = [src] if src else []
            merged[key] = e
    rows = sorted(merged.values(), key=lambda x: str(x.get("timestamp", "")))
    return rows[:max_rows] if max_rows else rows


# ---------------------------------------------------------------------------
# 6. Honest hash status (the old code reported "match" even when nothing was checked)
# ---------------------------------------------------------------------------
def hash_status(ev: Dict[str, Any]) -> str:
    recorded = ev.get("sha256_hash")
    if not recorded:
        return "not recorded"
    expected = ev.get("expected_sha256")
    if not expected:
        return "recorded (not re-verified)"
    return "match" if recorded == expected else "MISMATCH"


# ---------------------------------------------------------------------------
# 7. HTML escaping helper
# ---------------------------------------------------------------------------
def esc(v: Any) -> str:
    return html.escape("" if v is None else str(v))


# ---------------------------------------------------------------------------
# 8. Executive summary built from the real findings
# ---------------------------------------------------------------------------
def build_executive_summary(case_name: str, n_evidence: int, n_events: int,
                            detections: List[Dict[str, Any]], hosts: List[str],
                            users: List[str], dwell: str,
                            first_seen: Optional[str] = None, last_seen: Optional[str] = None,
                            facts: Optional[Dict[str, Any]] = None) -> str:
    """facts (optional, computed from the evidence by your parsers):
       initial_access, ransomware_family, encrypted_files, exfil_gib, exfil_dest"""
    facts = facts or {}
    tactics = {d.get("mitre_tactic") for d in detections}
    ordered = [t for t in TACTIC_ORDER if t in tactics] + sorted(t for t in tactics if t not in TACTIC_ORDER and t)
    crit = sum(1 for d in detections if _sev(d) == "critical")
    p = [f"[DRAFT] Forensic investigation report for incident '{case_name}'. "
         f"{n_evidence} evidence artifact(s) were ingested; upload-time SHA-256 values are recorded and generation-time file checks are reported per artifact where available. "
         f"{n_events} normalized events were analyzed."]
    if first_seen and last_seen:
        p.append(f"Attack activity ran from {first_seen} to {last_seen} UTC (dwell time {dwell}).")
    if facts.get("initial_access"):
        p.append(f"Likely initial access: {facts['initial_access']}.")
    p.append(f"{len(detections)} distinct detections ({crit} critical) span these tactics: "
             f"{', '.join(ordered) or 'none'}. "
             f"{len(hosts)} host(s) with matching findings ({', '.join(hosts) or 'none'}) and {len(users)} account(s) "
             f"observed in matching findings/events ({', '.join(users) or 'none'}).")
    if facts.get("exfil_gib"):
        p.append(f"Transfer detections covered about {facts['exfil_gib']} GiB of recorded bytes; direction, destination, and intent require review.")
    if facts.get("encrypted_files"):
        p.append(f"An impact detection referenced {facts['encrypted_files']} file operation(s); encryption and attribution have not been independently confirmed.")
    return " ".join(p)
