"""DPU resource budgets: Arm cores, memory and storage per device, a slice reserved for platform (DOCA)
services, and per-service requests. Deploy plans are blocked when a request does not fit."""
from .common import Problem, finite

RESOURCES = ("arm_cores", "memory_gb", "storage_gb")
# Published specifications; a reported or configured capacity always wins.
MODELS = {"BlueField-3": {"arm_cores": 16, "memory_gb": 32, "storage_gb": 120},
          "BlueField-2": {"arm_cores": 8, "memory_gb": 16, "storage_gb": 64}}
RESERVED = {"arm_cores": 2, "memory_gb": 4, "storage_gb": 10}
LIMITS = {"arm_cores": (1, 64), "memory_gb": (0.25, 512), "storage_gb": (0, 4096)}


def validate_resources(value):
    if not isinstance(value, dict) or not value or set(value) - set(RESOURCES):
        raise Problem(f"resources may set {', '.join(RESOURCES)}")
    out = {}
    for key, v in value.items():
        lo, hi = LIMITS[key]
        if key == "arm_cores" and type(v) is not int:
            raise Problem("arm_cores must be an integer")
        out[key] = finite(v, key, lo, hi)
    return out


def device_capacity(d):
    """(capacity, reserved) for a device, or (None, None) when its model is unknown."""
    if isinstance(d.get("capacity"), dict):
        return d["capacity"], d.get("reserved") or RESERVED
    for model, cap in MODELS.items():
        if model in (d.get("model") or ""):
            return cap, RESERVED
    return None, None


def usage(services, replacing=None):
    used = {k: 0 for k in RESOURCES}
    for s in services:
        if s.get("name") == replacing:
            continue
        for k in RESOURCES:
            used[k] += (s.get("resources") or {}).get(k, 0)
    return used


def budget_blockers(d, service, resources):
    cap, reserved = device_capacity(d)
    if not resources:
        return []
    if cap is None:
        return [f"{d['id']}: device capacity is unknown, so a resource request cannot be checked"]
    used = usage(d.get("services") or [], replacing=service)
    out = []
    for k, want in resources.items():
        free = cap[k] - reserved.get(k, 0) - used[k]
        if want > free:
            out.append(f"{d['id']}: {service} needs {want} {k.replace('_', ' ')} but {round(free, 2)} are free "
                       f"({cap[k]} total, {reserved.get(k, 0)} reserved for platform services, {round(used[k], 2)} in use)")
    return out


class BudgetMixin:
    def budget(self, device_id):
        with self.lock:
            d = self.device(device_id)
        cap, reserved = device_capacity(d)
        services = d.get("services") or []
        used = usage(services)
        return {"device": device_id, "model": d.get("model"), "capacity": cap, "reserved": reserved, "used": used,
                "free": {k: round(cap[k] - reserved.get(k, 0) - used[k], 2) for k in RESOURCES} if cap else None,
                "services": [{"name": s["name"], "state": s.get("state"), "resources": s.get("resources") or {}} for s in services],
                "source": "reported" if isinstance(d.get("capacity"), dict) else "model specification" if cap else "unknown"}
