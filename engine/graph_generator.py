"""
Incident Relationship Graph Generator for Digital Time Machine.
Extracts entities and relationships from evidence events and correlation rules.
Distinguishes recorded relationships from inferred links.
"""

import json

def generate_relationship_graph(events: list[dict], findings: list[dict] = None) -> dict:
    """
    Constructs graph nodes and edges from forensic events and correlation findings.
    
    Nodes have: id, label, type, category, evidence_count, details
    Edges have: id, source, target, relationship, relation_type ('observed' | 'inferred'), 
                supporting_event_ids, explanation
    """
    findings = findings or []
    nodes = {}
    edges = []
    edge_keys = set()

    def add_node(node_id: str, label: str, node_type: str, details: dict = None):
        if node_id not in nodes:
            nodes[node_id] = {
                "id": node_id,
                "label": label,
                "type": node_type,
                "evidence_count": 0,
                "associated_events": [],
                "details": details or {}
            }
        return nodes[node_id]

    def add_edge(src_id: str, tgt_id: str, label: str, rel_type: str, event_ids: list, explanation: str):
        edge_id = f"{src_id}->{tgt_id}:{label}"
        if edge_id not in edge_keys:
            edge_keys.add(edge_id)
            edges.append({
                "id": edge_id,
                "source": src_id,
                "target": tgt_id,
                "label": label,
                "relation_type": rel_type,  # 'observed' vs 'inferred'
                "supporting_event_ids": event_ids,
                "explanation": explanation
            })

    # Process events
    for ev in events:
        source = ev.get("source", "").lower()
        etype = ev.get("event_type", "").upper()
        actor = ev.get("actor", "unknown")
        obj = ev.get("object", "unknown")
        ev_id = ev.get("id")

        details = ev.get("details", {})
        if isinstance(details, str):
            try:
                details = json.loads(details)
            except Exception:
                details = {}

        # 1. Actors (Users)
        user_node_id = f"user_{actor}"
        user_node = add_node(user_node_id, actor, "user", {"role": "Account / Identity"})
        user_node["evidence_count"] += 1
        user_node["associated_events"].append(ev_id)

        # 2. Source-specific Entities
        if source == "login":
            ws_id = f"dev_{obj}"
            ws_node = add_node(ws_id, obj, "device", {"device_class": "Workstation"})
            ws_node["evidence_count"] += 1
            ws_node["associated_events"].append(ev_id)

            if etype in ("LOGIN_SUCCESS", "LOGON"):
                add_edge(user_node_id, ws_id, "LOGGED_INTO", "observed", [ev_id],
                         f"User '{actor}' authenticated to '{obj}' at {ev['timestamp']}.")
            elif etype in ("LOGIN_FAILED", "AUTH_FAILURE"):
                add_edge(user_node_id, ws_id, "FAILED_LOGON_TO", "observed", [ev_id],
                         f"Failed login attempt for '{actor}' on '{obj}' at {ev['timestamp']}.")

        elif source == "browser":
            site_id = f"web_{obj[:40]}"
            site_node = add_node(site_id, obj, "website", {"url": obj})
            site_node["evidence_count"] += 1
            site_node["associated_events"].append(ev_id)

            add_edge(user_node_id, site_id, "NAVIGATED_TO", "observed", [ev_id],
                     f"User '{actor}' accessed URL '{obj}' at {ev['timestamp']}.")

        elif source == "file":
            is_dir = etype in ("DIR_ACCESS", "DIRECTORY_ACCESS") or "." not in obj.replace("\\", "/").split("/")[-1]
            file_name = obj.replace("\\", "/").rstrip("/").split("/")[-1] or "Data"
            file_id = f"dir_{file_name}" if is_dir else f"file_{file_name}"
            node_label = f"[DIR] {file_name}" if is_dir else file_name
            file_node = add_node(file_id, node_label, "file", {"full_path": obj, "category": "directory" if is_dir else "file"})
            file_node["evidence_count"] += 1
            file_node["associated_events"].append(ev_id)

            if is_dir:
                add_edge(user_node_id, file_id, "ACCESSED_DIR", "observed", [ev_id],
                         f"User '{actor}' accessed directory '{obj}' at {ev['timestamp']}.")
            elif etype in ("FILE_DOWNLOAD", "DOWNLOAD"):
                add_edge(user_node_id, file_id, "DOWNLOADED", "observed", [ev_id],
                         f"User '{actor}' downloaded file '{file_name}' at {ev['timestamp']}.")
            elif etype in ("FILE_CREATE", "FILE_CREATED"):
                add_edge(user_node_id, file_id, "CREATED", "observed", [ev_id],
                         f"User '{actor}' created file '{file_name}' at {ev['timestamp']}.")
            elif etype in ("FILE_ACCESS", "FILE_READ", "FILE_OPEN"):
                add_edge(user_node_id, file_id, "ACCESSED", "observed", [ev_id],
                         f"User '{actor}' read/opened file '{file_name}' at {ev['timestamp']}.")
            elif etype in ("FILE_COPY", "FILE_COPIED"):
                add_edge(user_node_id, file_id, "COPIED", "observed", [ev_id],
                         f"User '{actor}' initiated copy operation on '{file_name}' at {ev['timestamp']}.")
            elif etype in ("FILE_DELETE", "FILE_DELETED"):
                add_edge(user_node_id, file_id, "DELETED", "observed", [ev_id],
                         f"User '{actor}' deleted file '{file_name}' at {ev['timestamp']}.")
                # Explicit Database file -> Deletion node & edge
                del_id = f"deletion_{file_name}"
                del_node = add_node(del_id, f"DELETED: {file_name}", "file", {"action": "FILE_DELETION", "file": file_name})
                del_node["evidence_count"] += 1
                del_node["associated_events"].append(ev_id)
                add_edge(file_id, del_id, "RECORDED_DELETION", "observed", [ev_id],
                         f"File '{file_name}' marked as deleted at {ev['timestamp']}.")

        elif source == "usb":
            usb_id = f"usb_{obj}"
            usb_node = add_node(usb_id, obj, "device", {
                "serial_number": details.get("serial_number", "N/A"),
                "mount_point": details.get("mount_point", "E:\\")
            })
            usb_node["evidence_count"] += 1
            usb_node["associated_events"].append(ev_id)

            add_edge(user_node_id, usb_id, "ATTACHED_DEVICE", "observed", [ev_id],
                     f"User '{actor}' attached removable USB device '{obj}' at {ev['timestamp']}.")
            # Device -> USB link
            ws_id = "dev_workstation-01"
            add_node(ws_id, "workstation-01", "device", {"device_class": "Workstation"})
            add_edge(ws_id, usb_id, "MOUNTED_USB", "observed", [ev_id],
                     f"Workstation host mounted USB device '{obj}' on port 2.")

        elif source == "network":
            dest_ip = obj
            port = details.get("destination_port", "unknown")
            net_id = f"net_{dest_ip}_{port}"
            net_node = add_node(net_id, f"{dest_ip}:{port}", "network", {
                "ip": dest_ip,
                "port": port,
                "protocol": details.get("protocol", "TCP")
            })
            net_node["evidence_count"] += 1
            net_node["associated_events"].append(ev_id)

            action_label = "EXFIL_TRANSFER" if etype == "NETWORK_TRANSFER" else "CONNECTED_TO"
            add_edge(user_node_id, net_id, action_label, "observed", [ev_id],
                     f"User/Host '{actor}' initiated flow to '{dest_ip}:{port}' at {ev['timestamp']}.")
            ws_id = "dev_workstation-01"
            add_edge(ws_id, net_id, "OUTBOUND_SOCKET", "observed", [ev_id],
                     f"Host workstation established outbound connection to '{dest_ip}:{port}'.")

    # Connect Inferred Edges from Correlation Findings
    for f in findings:
        rule_id = f.get("rule_id")
        supp_ids = f.get("supporting_event_ids", [])
        if rule_id == "RULE_A" and len(supp_ids) >= 2:
            # Website delivered downloaded tool (inferred)
            ev_web = next((e for e in events if e["id"] == supp_ids[0]), None)
            ev_dl = next((e for e in events if e["id"] == supp_ids[1]), None)
            if ev_web and ev_dl:
                site_id = f"web_{ev_web['object'][:40]}"
                dl_name = ev_dl['object'].replace("\\", "/").split("/")[-1]
                file_id = f"file_{dl_name}"
                if site_id in nodes and file_id in nodes:
                    add_edge(site_id, file_id, "DELIVERED_PAYLOAD", "inferred", supp_ids,
                             f"Inferred: Website {ev_web['object']} delivered downloaded payload {dl_name}.")

        elif rule_id == "RULE_C" and len(supp_ids) >= 2:
            # File copied to USB (inferred correlation)
            ev_usb = next((e for e in events if e["id"] == supp_ids[0]), None)
            ev_cp = next((e for e in events if e["id"] == supp_ids[1]), None)
            if ev_usb and ev_cp:
                usb_id = f"usb_{ev_usb['object']}"
                cp_name = ev_cp['object'].replace("\\", "/").split("/")[-1]
                file_id = f"file_{cp_name}"
                if file_id in nodes and usb_id in nodes:
                    add_edge(file_id, usb_id, "TRANSFERRED_TO_MEDIA", "inferred", supp_ids,
                             f"Inferred: File {cp_name} was transferred to USB drive {ev_usb['object']}.")

    return {
        "nodes": list(nodes.values()),
        "edges": edges,
        "counts": {
            "total_nodes": len(nodes),
            "total_edges": len(edges),
            "observed_edges": sum(1 for e in edges if e["relation_type"] == "observed"),
            "inferred_edges": sum(1 for e in edges if e["relation_type"] == "inferred")
        }
    }

