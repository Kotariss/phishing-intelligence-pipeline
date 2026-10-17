"""
Initializes the database schema and loads the 175-brand registry into the database.
"""

import os
import sys

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(ROOT_DIR, "services", "worker", "src"))

from db.database import init_db, SessionLocal
from db.models import BrandAllowlistModel
from brands.matcher import get_brand_registry

def setup_database():
    print("Initializing Phishing Intelligence Pipeline database tables...")
    init_db()
    
    reg = get_brand_registry()
    db = SessionLocal()
    
    try:
        inserted = 0
        for b in reg.brands:
            existing = db.query(BrandAllowlistModel).filter(BrandAllowlistModel.brand_id == b["brand_id"]).first()
            if not existing:
                model = BrandAllowlistModel(
                    brand_id=b["brand_id"],
                    display_name=b["display_name"],
                    category=b.get("category", "general"),
                    allowed_domains=b.get("official_domains", []),
                    allowed_patterns=b.get("allowed_domain_patterns", []),
                    aliases=b.get("aliases", [])
                )
                db.add(model)
                inserted += 1
        db.commit()
        print(f"Loaded {inserted} brands into database allowlist table (Total brands: {len(reg.brands)}).")
    finally:
        db.close()

    print("Database initialization complete.")

if __name__ == "__main__":
    setup_database()
