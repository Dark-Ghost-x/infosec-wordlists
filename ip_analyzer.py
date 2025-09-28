import requests as rq
import time as tm
import sys as s
import os as o
import json

class C:
    R, G, Y, B, P, C, W = '\033[91m', '\033[92m', '\033[93m', '\033[94m', '\033[95m', '\033[96m', '\033[97m'
    BD, ED = '\033[1m', '\033[0m'

def cs(): o.system('clear' if o.name == 'posix' else 'cls')

def tw(t, c=C.W, d=0.01):
    for ch in t:
        print(c + ch + C.ED, end='', flush=True)
        tm.sleep(d)
    print()

def al():
    lg = [
        "███████████████████████████",
        "███████▀▀▀░░░░░░░▀▀▀███████",
        "████▀░░░░░░░░░░░░░░░░░▀████",
        "███│░░░░░░░░░░░░░░░░░░░│███",
        "██▌│░░░░░░░░░░░░░░░░░░░│▐██",
        "██░└┐░░░░░░░░░░░░░░░░░┌┘░██",
        "██░░└┐░░░░░░░░░░░░░░░┌┘░░██",
        "██░░┌┘▄▄▄▄▄░░░░░▄▄▄▄▄└┐░░██",
        "██▌░│██████▌░░░▐██████│░▐██",
        "███░│▐███▀▀░░▄░░▀▀███▌│░███",
        "██▀─┘░░░░░░░▐█▌░░░░░░░└─▀██",
        "██▄░░░▄▄▄▓░░▀█▀░░▓▄▄▄░░░▄██",
        "████▄─┘██▌░░░░░░░▐██└─▄████",
        "█████░░▐█─┬┬┬┬┬┬┬─█▌░░█████",
        "████▌░░░▀┬┼┼┼┼┼┼┼┬▀░░░▐████",
        "█████▄░░░└┴┴┴┴┴┴┴┘░░░▄█████",
        "███████▄░░░░░░░░░░░▄███████",
        "██████████▄▄▄▄▄▄▄██████████",
        "███████████████████████████"
    ]
    for ln in lg:
        print(C.R + ln + C.ED)
        tm.sleep(0.03)

def pb(desc, dur=2):
    print(f"{C.B}{desc}{C.ED}")
    for i in range(101):
        b = "█" * (i//4)
        sp = " " * (25-i//4)
        cl = [C.R, C.G, C.Y, C.B, C.P, C.C][i//17]
        s.stdout.write(f"\r{cl}[{b}{sp}] {i}%{C.ED}")
        s.stdout.flush()
        tm.sleep(dur/100)

def gpi():
    srvs = [
        'https://api.ipify.org',
        'https://ident.me',
        'https://checkip.amazonaws.com',
        'https://api.myip.com',
        'https://ip.seeip.org'
    ]
    for srv in srvs:
        try:
            rs = rq.get(srv, timeout=5)
            if rs.status_code == 200:
                ip = rs.text.strip()
                if ip and '.' in ip:
                    return ip
        except:
            continue
    return None

def gdii(ip):
    apis = [
        {'url': f'http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,query'},
        {'url': f'https://ipapi.co/{ip}/json/'},
        {'url': f'https://ipinfo.io/{ip}/json'},
        {'url': f'http://www.geoplugin.net/json.gp?ip={ip}'}
    ]

    for api in apis:
        try:
            rs = rq.get(api['url'], timeout=10)
            if rs.status_code == 200:
                data = rs.json()

                if 'ip-api.com' in api['url']:
                    if data.get('status') == 'success':
                        return {
                            'country': data.get('country', 'Unknown'),
                            'city': data.get('city', 'Unknown'),
                            'region': data.get('regionName', 'Unknown'),
                            'isp': data.get('isp', 'Unknown'),
                            'lat': data.get('lat', 'Unknown'),
                            'lon': data.get('lon', 'Unknown'),
                            'timezone': data.get('timezone', 'Unknown'),
                            'asn': data.get('as', 'Unknown')
                        }

                elif 'ipapi.co' in api['url']:
                    return {
                        'country': data.get('country_name', 'Unknown'),
                        'city': data.get('city', 'Unknown'),
                        'region': data.get('region', 'Unknown'),
                        'isp': data.get('org', 'Unknown'),
                        'lat': data.get('latitude', 'Unknown'),
                        'lon': data.get('longitude', 'Unknown'),
                        'timezone': data.get('timezone', 'Unknown'),
                        'asn': data.get('asn', 'Unknown')
                    }

                elif 'ipinfo.io' in api['url']:
                    loc = data.get('loc', '').split(',')
                    return {
                        'country': data.get('country', 'Unknown'),
                        'city': data.get('city', 'Unknown'),
                        'region': data.get('region', 'Unknown'),
                        'isp': data.get('org', 'Unknown'),
                        'lat': loc[0] if len(loc) > 0 else 'Unknown',
                        'lon': loc[1] if len(loc) > 1 else 'Unknown',
                        'timezone': data.get('timezone', 'Unknown')
                    }

                elif 'geoplugin.net' in api['url']:
                    return {
                        'country': data.get('geoplugin_countryName', 'Unknown'),
                        'city': data.get('geoplugin_city', 'Unknown'),
                        'region': data.get('geoplugin_region', 'Unknown'),
                        'lat': data.get('geoplugin_latitude', 'Unknown'),
                        'lon': data.get('geoplugin_longitude', 'Unknown'),
                        'timezone': data.get('geoplugin_timezone', 'Unknown')
                    }

        except:
            continue

    return None

def dvp(ip):
    try:
        rs = rq.get(f'http://ip-api.com/json/{ip}', timeout=5)
        if rs.status_code == 200:
            data = rs.json()
            if data.get('status') == 'success':
                isp = data.get('isp', '').lower()
                org = data.get('org', '').lower()
                vpn_indicators = ['vpn', 'proxy', 'tor', 'anonymous', 'host', 'server', 'cloud']
                return any(ind in isp or ind in org for ind in vpn_indicators)
    except:
        pass
    return False

def dc(oi, vi, oinf, vinf):
    print(f"\n{C.G}{'='*60}{C.ED}")
    print(f"{C.BD}{C.C}          IP ANALYZER REPORT{C.ED}")
    print(f"{C.G}{'='*60}{C.ED}")

    vd = dvp(vi)

    print(f"\n{C.BD}{C.Y}REAL IP:{C.ED}")
    print(f"IP: {C.G}{oi}{C.ED}")
    if oinf:
        print(f"Country: {C.G}{oinf.get('country', 'Unknown')}{C.ED}")
        print(f"City: {C.G}{oinf.get('city', 'Unknown')}{C.ED}")
        print(f"Region: {C.G}{oinf.get('region', 'Unknown')}{C.ED}")
        print(f"ISP: {C.C}{oinf.get('isp', 'Unknown')}{C.ED}")
        print(f"Coordinates: {C.P}{oinf.get('lat', 'Unknown')}, {oinf.get('lon', 'Unknown')}{C.ED}")
        print(f"Timezone: {C.P}{oinf.get('timezone', 'Unknown')}{C.ED}")

    print(f"\n{C.BD}{C.R}TARGET IP:{C.ED}")
    print(f"IP: {C.R}{vi}{C.ED}")
    if vinf:
        print(f"Country: {C.G}{vinf.get('country', 'Unknown')}{C.ED}")
        print(f"City: {C.G}{vinf.get('city', 'Unknown')}{C.ED}")
        print(f"Region: {C.G}{vinf.get('region', 'Unknown')}{C.ED}")
        print(f"ISP: {C.C}{vinf.get('isp', 'Unknown')}{C.ED}")
        print(f"Coordinates: {C.P}{vinf.get('lat', 'Unknown')}, {vinf.get('lon', 'Unknown')}{C.ED}")
        print(f"Timezone: {C.P}{vinf.get('timezone', 'Unknown')}{C.ED}")

    print(f"\n{C.BD}{C.P}SECURITY:{C.ED}")
    if vd:
        print(f"Status: {C.R}VPN/PROXY DETECTED{C.ED}")
        print(f"Type: {C.R}Proxy Service{C.ED}")
    else:
        print(f"Status: {C.G}CLEAN IP{C.ED}")
        print(f"Type: {C.G}Normal ISP{C.ED}")

def mn():
    cs()
    print(f"\n{C.BD}{C.C}Initializing IP Analyzer...{C.ED}\n")
    tm.sleep(1)
    al()
    print(f"\n{C.BD}{C.G}╔{'═'*56}╗{C.ED}")
    print(f"{C.BD}{C.G}║  Creator: t.me/Red_Rooted_Ghost{' '*26}║{C.ED}")
    print(f"{C.BD}{C.G}╚{'═'*56}╝{C.ED}")
    tm.sleep(1)

    tw("Starting analysis engine...", C.Y)
    tm.sleep(1)

    print(f"\n{C.G}Enter target IP address:{C.ED}")
    vip = input(f"{C.B}>>> {C.ED}").strip()

    if not vip:
        print(f"\n{C.R}No IP provided!{C.ED}")
        return

    print(f"\n{C.BD}{C.C}Analyzing target...{C.ED}")

    pb("Locating real IP", 1.5)
    oip = gpi()

    if not oip:
        print(f"\n{C.R}Failed to get real IP{C.ED}")
        return

    pb("Scanning target IP", 2)
    vinf = gdii(vip)

    pb("Collecting real IP data", 2)
    oinf = gdii(oip)

    pb("Finalizing scan", 1)
    dc(oip, vip, oinf, vinf)

    print(f"\n{C.BD}{C.G}{'='*60}{C.ED}")
    print(f"{C.BD}{C.G}SCAN COMPLETED{C.ED}")
    print(f"Real IP: {C.G}{oip}{C.ED}")
    print(f"Target IP: {C.R}{vip}{C.ED}")
    print(f"{C.W}For security research only!{C.ED}")
    print(f"{C.R}{'='*60}{C.ED}")

if __name__ == "__main__":
    try:
        import requests
    except:
        print(f"{C.R}Install: pip install requests{C.ED}")
        exit(1)

    try:
        mn()
    except KeyboardInterrupt:
        print(f"\n{C.R}Interrupted{C.ED}")
    except Exception as e:
        print(f"\n{C.R}Error{C.ED}")
