import os
from sqlalchemy import create_engine, Column, String, Boolean, DateTime, func, Text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Get database URL from environment variable or use default SQLite URL as fallback
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./ip_logs.db")

# Create SQLAlchemy engine
if DATABASE_URL.startswith("sqlite"):
    engine = create_engine(
        DATABASE_URL, connect_args={"check_same_thread": False}
    )
else:
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
    gclid = Column(Text, nullable=True)  # New column to store actual GCLID values
    is_known_ip = Column(Boolean, default=False)
    placement = Column(String, nullable=True)
    created_at = Column(DateTime, default=func.now())
    
    def __repr__(self):
        return f"<IPLog ip_address={self.ip_address}, gclid={self.gclid}>"

# Function to get database session
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Create all tables in the database (if they don't exist)
def create_tables():
    Base.metadata.create_all(bind=engine)

# Initialize database
def init_db():
    create_tables()
    # Data migration code removed as per user request 