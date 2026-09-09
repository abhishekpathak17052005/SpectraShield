from fastapi import APIRouter
from app.database import scan_collection

router = APIRouter(tags=["history"])


@router.get("/history")
def get_history():
    records = list(scan_collection.find({}, {"_id": 0}))
    return records[::-1]  # newest first


@router.get("/history/count")
def get_history_count():
    total_scans = scan_collection.count_documents({})
    return {"total_scans": total_scans}


@router.delete("/history")
def clear_history():
    scan_collection.delete_many({})
    return {"message": "All logs cleared"}


@router.delete("/history/{scan_id}")
def delete_scan(scan_id: str):
    result = scan_collection.delete_one({"id": scan_id})
    if result.deleted_count == 1:
        return {"message": f"Scan {scan_id} deleted"}
    return {"message": "Scan ID not found"}