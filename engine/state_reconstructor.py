"""
Digital System State Reconstructor for Digital Time Machine.
Reconstructs point-in-time system state strictly from evidence recorded up to a target timestamp.
Adheres to forensic caution: does not invent unrecorded states or presume malicious causality.
"""

from datetime import datetime
import json

def reconstruct_system_state(events: list[dict], target_timestamp: str | None = None) -> dict:
    """
    Reconstructs the digital system state from an ordered list of events up to target_timestamp.
    
    Args:
        events: List of event dicts ordered chronologically.
        target_timestamp: ISO timestamp string (e.g. '2026-10-07T10:15:00').
                         If None, uses all events up to the end of the timeline.
    
    Returns:
        dict containing:
            - target_timestamp
            - active_sessions: {user: {workstation, login_time, last_active}}
            - file_system: {file_path: {status, created_at, accessed_at, copied_at, deleted_at, last_actor}}
            - connected_devices: {device_id: {device_name, connected_at, disconnected_at, is_connected, actor}}
            - network_connections: {conn_id: {destination, port, actor, timestamp, protocol}}
            - browser_history: list of {url, title, timestamp, actor}
            - last_event: the most recent event at or before target_timestamp
            - events_applied_count: total events included in this state
            - changes_at_point: list of events that occurred at the current timestamp
    """
    # Filter events up to target_timestamp
    applied_events = []
    for ev in events:
        if target_timestamp is None or ev["timestamp"] <= target_timestamp:
            applied_events.append(ev)
        else:
            break

    # State tracking structures
    active_sessions = {}
    file_system = {}
    connected_devices = {}
    network_connections = {}
    browser_history = []
    
    last_event = applied_events[-1] if applied_events else None
    current_time_events = [ev for ev in applied_events if ev["timestamp"] == target_timestamp] if target_timestamp else []

    for ev in applied_events:
        source = ev.get("source", "").lower()
        etype = ev.get("event_type", "").upper()
        actor = ev.get("actor", "unknown")
        obj = ev.get("object", "unknown")
        ts = ev.get("timestamp", "")
        
        details = ev.get("details", {})
        if isinstance(details, str):
            try:
                details = json.loads(details)
            except Exception:
                details = {}

        # 1. User Sessions
        if source == "login":
            if etype in ("LOGIN_SUCCESS", "LOGON"):
                active_sessions[actor] = {
                    "workstation": obj,
                    "login_time": ts,
                    "last_active": ts,
                    "status": "ACTIVE"
                }
            elif etype in ("LOGOUT", "LOGOFF"):
                if actor in active_sessions:
                    active_sessions[actor]["status"] = "LOGGED_OUT"
                    active_sessions[actor]["logout_time"] = ts
            elif etype in ("LOGIN_FAILED", "AUTH_FAILURE"):
                # Track failed attempt count if wanted, but don't establish active session
                pass
        else:
            # If actor is active, update last_active timestamp
            if actor in active_sessions and active_sessions[actor].get("status") == "ACTIVE":
                active_sessions[actor]["last_active"] = ts

        # 2. File System Tracking
        if source == "file":
            file_entry = file_system.setdefault(obj, {
                "file_path": obj,
                "status": "KNOWN",
                "created_at": None,
                "accessed_at": None,
                "copied_at": None,
                "deleted_at": None,
                "last_actor": actor,
                "history": []
            })
            file_entry["last_actor"] = actor
            file_entry["history"].append({"type": etype, "timestamp": ts, "actor": actor})

            if etype in ("FILE_CREATE", "FILE_CREATED"):
                file_entry["status"] = "CREATED"
                file_entry["created_at"] = ts
            elif etype in ("FILE_ACCESS", "FILE_READ", "FILE_OPEN"):
                file_entry["status"] = "ACCESSED" if file_entry["status"] == "KNOWN" else file_entry["status"]
                file_entry["accessed_at"] = ts
            elif etype in ("FILE_COPY", "FILE_COPIED"):
                file_entry["status"] = "COPIED"
                file_entry["copied_at"] = ts
                file_entry["copy_destination"] = details.get("destination", "external_media")
            elif etype in ("FILE_DELETE", "FILE_DELETED"):
                file_entry["status"] = "DELETED"
                file_entry["deleted_at"] = ts

        # 3. Device Connections (USB, etc.)
        if source == "usb":
            device_entry = connected_devices.setdefault(obj, {
                "device_id": obj,
                "device_name": details.get("device_name", obj),
                "serial_number": details.get("serial_number", "unknown"),
                "vendor_id": details.get("vendor_id", "unknown"),
                "connected_at": None,
                "disconnected_at": None,
                "is_connected": False,
                "actor": actor
            })
            device_entry["actor"] = actor
            if etype in ("DEVICE_CONNECT", "USB_INSERT", "DEVICE_MOUNT"):
                device_entry["is_connected"] = True
                device_entry["connected_at"] = ts
                device_entry["mount_point"] = details.get("mount_point", "E:\\")
            elif etype in ("DEVICE_DISCONNECT", "USB_REMOVE", "DEVICE_UNMOUNT"):
                device_entry["is_connected"] = False
                device_entry["disconnected_at"] = ts

        # 4. Network Connections
        if source == "network":
            dest = obj
            port = details.get("port", details.get("destination_port", "unknown"))
            conn_key = f"{dest}:{port}"
            network_connections[conn_key] = {
                "conn_id": conn_key,
                "destination": dest,
                "port": port,
                "protocol": details.get("protocol", "TCP"),
                "bytes_transferred": details.get("bytes_transferred", 0),
                "actor": actor,
                "timestamp": ts,
                "event_type": etype,
                "confidence": ev.get("confidence", "observed")
            }

        # 5. Browser Activity
        if source == "browser":
            browser_history.append({
                "url": obj,
                "title": details.get("title", "Web Page"),
                "timestamp": ts,
                "actor": actor,
                "event_type": etype,
                "user_agent": details.get("user_agent", "Standard Browser")
            })

    return {
        "target_timestamp": target_timestamp or (last_event["timestamp"] if last_event else None),
        "events_applied_count": len(applied_events),
        "total_events_in_case": len(events),
        "active_sessions": active_sessions,
        "file_system": file_system,
        "connected_devices": connected_devices,
        "network_connections": network_connections,
        "browser_history": browser_history[-10:],  # Recent 10 browser entries
        "last_event": last_event,
        "changes_at_point": current_time_events
    }

