from pymongo import MongoClient, ASCENDING

# Connect to local MongoDB
client = MongoClient("mongodb://localhost:27017/")

# Create / use database
db = client["spectrashield_db"]

# Create / use collection (primary)
scans_collection = db["scans"]


def _drop_scan_ttl_indexes() -> None:
	# Keep scan history for lifetime: remove any legacy TTL index if present.
	for index_name, details in scans_collection.index_information().items():
		if "expireAfterSeconds" in details:
			scans_collection.drop_index(index_name)


_drop_scan_ttl_indexes()

scans_collection.create_index([("thread_id", ASCENDING)])
scans_collection.create_index([("linkedin_thread_id", ASCENDING)], unique=True, sparse=True)

# Backward-compatible alias used by older modules
scan_collection = scans_collection

# Threat intelligence feed (OpenPhish) – URL is unique key
threat_feed_collection = db["threat_feed"]
threat_feed_collection.create_index([("url", ASCENDING)], unique=True)

# VirusTotal URL intelligence cache (24h)
vt_cache_collection = db["vt_url_cache"]
vt_cache_collection.create_index([("url", ASCENDING)], unique=True)