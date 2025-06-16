#!/usr/bin/env python3
"""
Script to initialize the PostgreSQL database tables without migrating existing data.
"""
import os
from sqlalchemy import create_engine, Column, String, Boolean, DateTime, func, Text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Get database URL from environment variable
DATABASE_URL = os.getenv("DATABASE_URL")

print(f"Connecting to database: {DATABASE_URL}")

# Create SQLAlchemy engine
engine = create_engine(DATABASE_URL)

# Create session factory
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Create declarative base
Base = declarative_base()

# Define IP Log model
class IPLog(Base):
    __tablename__ = "ip_logs"
    
    ip_address = Column(String, primary_key=True, index=True)
    has_gclid = Column(Boolean, default=False)  # Keeping for backward compatibility
    gclid = Column(Text, nullable=True)  # Store actual GCLID values
    is_known_ip = Column(Boolean, default=False)
    placement = Column(String, nullable=True)
    created_at = Column(DateTime, default=func.now())
    
    def __repr__(self):
        return f"<IPLog ip_address={self.ip_address}, gclid={self.gclid}>"

if __name__ == "__main__":
    print("Creating database tables...")
    try:
        Base.metadata.create_all(bind=engine)
        print("✅ Database tables created successfully!")
    except Exception as e:
        print(f"❌ Error creating database tables: {e}")
    
    print("\nYou can now run the application with: python main.py") 