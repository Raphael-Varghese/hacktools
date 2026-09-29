#!/usr/bin/env python3
import asyncio
import json
import os
import sys
from typing import Dict, List, Optional, Tuple
import click
import httpx
from rich.console import Console
from rich.table import Table
console = Console()
SITES = {
    "GitHub": {"url": "https://github.com/{}", "method": "status", "found": 200, "missing": 404},
    "GitLab": {"url": "https://gitlab.com/{}", "method": "status", "found": 200, "missing": 404},
    "Twitter/X": {"url": "https://x.com/{}", "method": "status", "found": 200, "missing": 404},
    "Instagram": {"url": "https://www.instagram.com/{}/", "method": "status", "found": 200, "missing": 404},
    "Facebook": {"url": "https://www.facebook.com/{}/", "method": "status", "found": 200, "missing": 404},
    "LinkedIn": {"url": "https://www.linkedin.com/in/{}/", "method": "status", "found": 200, "missing": 404},
    "Reddit": {"url": "https://www.reddit.com/user/{}/", "method": "status", "found": 200, "missing": 404},
    "TikTok": {"url": "https://www.tiktok.com/@{}", "method": "status", "found": 200, "missing": 404},
    "YouTube": {"url": "https://www.youtube.com/@{}", "method": "status", "found": 200, "missing": 404},
    "Pinterest": {"url": "https://www.pinterest.com/{}/", "method": "status", "found": 200, "missing": 404},
    "Tumblr": {"url": "https://{}.tumblr.com", "method": "status", "found": 200, "missing": 404},
    "Flickr": {"url": "https://www.flickr.com/people/{}/", "method": "status", "found": 200, "missing": 404},
    "Medium": {"url": "https://medium.com/@{}", "method": "status", "found": 200, "missing": 404},
    "Dev.to": {"url": "https://dev.to/{}", "method": "status", "found": 200, "missing": 404},
    "HackerNews": {"url": "https://news.ycombinator.com/user?id={}", "method": "status", "found": 200, "missing": 404},
    "ProductHunt": {"url": "https://www.producthunt.com/@{}", "method": "status", "found": 200, "missing": 404},
    "Quora": {"url": "https://www.quora.com/profile/{}", "method": "status", "found": 200, "missing": 404},
    "SoundCloud": {"url": "https://soundcloud.com/{}", "method": "status", "found": 200, "missing": 404},
    "Spotify": {"url": "https://open.spotify.com/user/{}", "method": "status", "found": 200, "missing": 404},
    "Bandcamp": {"url": "https://bandcamp.com/{}", "method": "status", "found": 200, "missing": 404},
    "Gravatar": {"url": "https://en.gravatar.com/{}", "method": "status", "found": 200, "missing": 404},
    "About.me": {"url": "https://about.me/{}", "method": "status", "found": 200, "missing": 404},
    "Slideshare": {"url": "https://www.slideshare.net/{}", "method": "status", "found": 200, "missing": 404},
    "Keybase": {"url": "https://keybase.io/{}", "method": "status", "found": 200, "missing": 404},
    "Pastebin": {"url": "https://pastebin.com/u/{}", "method": "status", "found": 200, "missing": 404},
    "TryHackMe": {"url": "https://tryhackme.com/p/{}", "method": "status", "found": 200, "missing": 404},
    "HackTheBox": {"url": "https://app.hackthebox.com/users/{}", "method": "status", "found": 200, "missing": 404},
    "Codeberg": {"url": "https://codeberg.org/{}", "method": "status", "found": 200, "missing": 404},
    "SourceForge": {"url": "https://sourceforge.net/u/{}/profile/", "method": "status", "found": 200, "missing": 404},
    "Bitbucket": {"url": "https://bitbucket.org/{}/", "method": "status", "found": 200, "missing": 404},
    "Docker Hub": {"url": "https://hub.docker.com/u/{}/", "method": "status", "found": 200, "missing": 404},
    "npm": {"url": "https://www.npmjs.com/~{}", "method": "status", "found": 200, "missing": 404},
    "PyPI": {"url": "https://pypi.org/user/{}/", "method": "status", "found": 200, "missing": 404},
    "RubyGems": {"url": "https://rubygems.org/profiles/{}", "method": "status", "found": 200, "missing": 404},
    "Crates.io": {"url": "https://crates.io/users/{}", "method": "status", "found": 200, "missing": 404},
    "NuGet": {"url": "https://www.nuget.org/profiles/{}", "method": "status", "found": 200, "missing": 404},
    "Steam": {"url": "https://steamcommunity.com/id/{}", "method": "status", "found": 200, "missing": 404},
    "Xbox": {"url": "https://www.xbox.com/en-US/gamer/{}", "method": "status", "found": 200, "missing": 404},
    "PlayStation": {"url": "https://my.playstation.com/profile/{}", "method": "status", "found": 200, "missing": 404},
    "Twitch": {"url": "https://www.twitch.tv/{}", "method": "status", "found": 200, "missing": 404},
    "Discord": {"url": "https://discord.com/users/{}", "method": "status", "found": 200, "missing": 404},
    "Mastodon": {"url": "https://mastodon.social/@{}", "method": "status", "found": 200, "missing": 404},
    "Telegram": {"url": "https://t.me/{}", "method": "status", "found": 200, "missing": 404},
    "Snapchat": {"url": "https://www.snapchat.com/add/{}", "method": "status", "found": 200, "missing": 404},
    "WhatsApp": {"url": "https://wa.me/{}", "method": "status", "found": 200, "missing": 404},
    "Vimeo": {"url": "https://vimeo.com/{}", "method": "status", "found": 200, "missing": 404},
    "Dailymotion": {"url": "https://www.dailymotion.com/{}", "method": "status", "found": 200, "missing": 404},
    "Tinder": {"url": "https://tinder.com/@{}", "method": "status", "found": 200, "missing": 404},
    "Bumble": {"url": "https://bumble.com/user/{}", "method": "status", "found": 200, "missing": 404},
    "OkCupid": {"url": "https://www.okcupid.com/profile/{}", "method": "status", "found": 200, "missing": 404},
    "Match": {"url": "https://www.match.com/profile/{}", "method": "status", "found": 200, "missing": 404},
    "eHarmony": {"url": "https://www.eharmony.com/profile/{}", "method": "status", "found": 200, "missing": 404},
    "PlentyOfFish": {"url": "https://www.pof.com/profile/{}", "method": "status", "found": 200, "missing": 404},
    "Badoo": {"url": "https://badoo.com/profile/{}", "method": "status", "found": 200, "missing": 404},
    "Meetup": {"url": "https://www.meetup.com/members/{}/", "method": "status", "found": 200, "missing": 404},
    "Eventbrite": {"url": "https://www.eventbrite.com/o/{}-{}/", "method": "status", "found": 200, "missing": 404},
    "Kickstarter": {"url": "https://www.kickstarter.com/profile/{}", "method": "status", "found": 200, "missing": 404},
    "Indiegogo": {"url": "https://www.indiegogo.com/individuals/{}/campaigns", "method": "status", "found": 200, "missing": 404},
    "Patreon": {"url": "https://www.patreon.com/{}", "method": "status", "found": 200, "missing": 404},
    "Ko-fi": {"url": "https://ko-fi.com/{}", "method": "status", "found": 200, "missing": 404},
    "Buy Me a Coffee": {"url": "https://www.buymeacoffee.com/{}", "method": "status", "found": 200, "missing": 404},
    "Liberapay": {"url": "https://liberapay.com/{}/", "method": "status", "found": 200, "missing": 404},
    "Open Collective": {"url": "https://opencollective.com/{}", "method": "status", "found": 200, "missing": 404},
    "Flattr": {"url": "https://flattr.com/@{}", "method": "status", "found": 200, "missing": 404},
    "Venmo": {"url": "https://venmo.com/{}", "method": "status", "found": 200, "missing": 404},
    "Cash App": {"url": "https://cash.app/${}", "method": "status", "found": 200, "missing": 404},
    "PayPal": {"url": "https://www.paypal.com/paypalme/{}", "method": "status", "found": 200, "missing": 404},
    "Stripe": {"url": "https://dashboard.stripe.com/{}", "method": "status", "found": 200, "missing": 404},
    "Square": {"url": "https://squareup.com/{}", "method": "status", "found": 200, "missing": 404},
    "Shopify": {"url": "https://{}.myshopify.com", "method": "status", "found": 200, "missing": 404},
    "Etsy": {"url": "https://www.etsy.com/shop/{}", "method": "status", "found": 200, "missing": 404},
    "Amazon": {"url": "https://www.amazon.com/gp/profile/amzn1.account.{}", "method": "status", "found": 200, "missing": 404},
    "eBay": {"url": "https://www.ebay.com/usr/{}", "method": "status", "found": 200, "missing": 404},
    "AliExpress": {"url": "https://www.aliexpress.com/store/{}", "method": "status", "found": 200, "missing": 404},
    "Walmart": {"url": "https://www.walmart.com/profile/{}", "method": "status", "found": 200, "missing": 404},
    "Target": {"url": "https://www.target.com/p/{}", "method": "status", "found": 200, "missing": 404},
    "Best Buy": {"url": "https://www.bestbuy.com/site/profile/{}", "method": "status", "found": 200, "missing": 404},
    "Newegg": {"url": "https://www.newegg.com/profile/{}", "method": "status", "found": 200, "missing": 404},
    "Overstock": {"url": "https://www.overstock.com/profile/{}", "method": "status", "found": 200, "missing": 404},
    "Wayfair": {"url": "https://www.wayfair.com/profile/{}", "method": "status", "found": 200, "missing": 404},
    "Houzz": {"url": "https://www.houzz.com/user/{}", "method": "status", "found": 200, "missing": 404},
    "Zillow": {"url": "https://www.zillow.com/profile/{}/", "method": "status", "found": 200, "missing": 404},
    "Realtor": {"url": "https://www.realtor.com/realestateagents/{}", "method": "status", "found": 200, "missing": 404},
    "Trulia": {"url": "https://www.trulia.com/profile/{}", "method": "status", "found": 200, "missing": 404},
    "Redfin": {"url": "https://www.redfin.com/agent/{}", "method": "status", "found": 200, "missing": 404},
    "Apartments": {"url": "https://www.apartments.com/profile/{}", "method": "status", "found": 200, "missing": 404},
    "Rent.com": {"url": "https://www.rent.com/profile/{}", "method": "status", "found": 200, "missing": 404},
    "Apartment Guide": {"url": "https://www.apartmentguide.com/profile/{}", "method": "status", "found": 200, "missing": 404},
    "ForRent": {"url": "https://www.forrent.com/profile/{}", "method": "status", "found": 200, "missing": 404},
    "Apartment List": {"url": "https://www.apartmentlist.com/profile/{}", "method": "status", "found": 200, "missing": 404},
    "PadMapper": {"url": "https://www.padmapper.com/profile/{}", "method": "status", "found": 200, "missing": 404},
    "Zumper": {"url": "https://www.zumper.com/profile/{}", "method": "status", "found": 200, "missing": 404},
    "RadPad": {"url": "https://www.radpad.com/profile/{}", "method": "status", "found": 200, "missing": 404},
    "Lovely": {"url": "https://www.lovely.com/profile/{}", "method": "status", "found": 200, "missing": 404},
    "Move.com": {"url": "https://www.move.com/profile/{}", "method": "status", "found": 200, "missing": 404},
    "Realtor.ca": {"url": "https://www.realtor.ca/agent/{}", "method": "status", "found": 200, "missing": 404},
    "Zoopla": {"url": "https://www.zoopla.co.uk/profile/{}", "method": "status", "found": 200, "missing": 404},
    "Rightmove": {"url": "https://www.rightmove.co.uk/profile/{}", "method": "status", "found": 200, "missing": 404},
    "OnTheMarket": {"url": "https://www.onthemarket.com/agent/{}", "method": "status", "found": 200, "missing": 404},
    "PrimeLocation": {"url": "https://www.primelocation.com/profile/{}", "method": "status", "found": 200, "missing": 404},
    "Domain": {"url": "https://www.domain.com.au/agent/{}", "method": "status", "found": 200, "missing": 404},
    "Realestate.com.au": {"url": "https://www.realestate.com.au/agent/{}", "method": "status", "found": 200, "missing": 404},
    "AllHomes": {"url": "https://www.allhomes.com.au/agent/{}", "method": "status", "found": 200, "missing": 404},
    "Homely": {"url": "https://www.homely.com.au/agent/{}", "method": "status", "found": 200, "missing": 404},
    "RateMyAgent": {"url": "https://www.ratemyagent.com.au/agent/{}", "method": "status", "found": 200, "missing": 404},
    "OpenAgent": {"url": "https://www.openagent.com.au/agent/{}", "method": "status", "found": 200, "missing": 404},
    "AgentFinder": {"url": "https://www.agentfinder.com.au/agent/{}", "method": "status", "found": 200, "missing": 404},
    "LocalAgentFinder": {"url": "https://www.localagentfinder.com.au/agent/{}", "method": "status", "found": 200, "missing": 404},
    "AgentSelect": {"url": "https://www.agentselect.com.au/agent/{}", "method": "status", "found": 200, "missing": 404},
    "AgentSpot": {"url": "https://www.agentspot.com.au/agent/{}", "method": "status", "found": 200, "missing": 404},
    "AgentProfile": {"url": "https://www.agentprofile.com.au/agent/{}", "method": "status", "found": 200, "missing": 404},
    "AgentDirectory": {"url": "https://www.agentdirectory.com.au/agent/{}", "method": "status", "found": 200, "missing": 404},
    "AgentListings": {"url": "https://www.agentlistings.com.au/agent/{}", "method": "status", "found": 200, "missing": 404},
    "AgentSearch": {"url": "https://www.agentsearch.com.au/agent/{}", "method": "status", "found": 200, "missing": 404},
    "AgentReviews": {"url": "https://www.agentreviews.com.au/agent/{}", "method": "status", "found": 200, "missing": 404},
    "AgentRatings": {"url": "https://www.agentratings.com.au/agent/{}", "method": "status", "found": 200, "missing": 404},
    "AgentFeedback": {"url": "https://www.agentfeedback.com.au/agent/{}", "method": "status", "found": 200, "missing": 404},
    "AgentTestimonials": {"url": "https://www.agenttestimonials.com.au/agent/{}", "method": "status", "found": 200, "missing": 404},
    "AgentRecommendations": {"url": "https://www.agentrecommendations.com.au/agent/{}", "method": "status", "found": 200, "missing": 404},
    "AgentReferrals": {"url": "https://www.agentreferrals.com.au/agent/{}", "method": "status", "found": 200, "missing": 404},
    "AgentNetwork": {"url": "https://www.agentnetwork.com.au/agent/{}", "method": "status", "found": 200, "missing": 404},
    "AgentCommunity": {"url": "https://www.agentcommunity.com.au/agent/{}", "method": "status", "found": 200, "missing": 404},
    "AgentForum": {"url": "https://www.agentforum.com.au/agent/{}", "method": "status", "found": 200, "missing": 404},
    "AgentBlog": {"url": "https://www.agentblog.com.au/agent/{}", "method": "status", "found": 200, "missing": 404},
    "AgentNews": {"url": "https://www.agentnews.com.au/agent/{}", "method": "status", "found": 200, "missing": 404},
    "AgentEvents": {"url": "https://www.agentevents.com.au/agent/{}", "method": "status", "found": 200, "missing": 404},
    "AgentTraining": {"url": "https://www.agenttraining.com.au/agent/{}", "method": "status", "found": 200, "missing": 404},
    "AgentResources": {"url": "https://www.agentresources.com.au/agent/{}", "method": "status", "found": 200, "missing": 404},
    "AgentTools": {"url": "https://www.agenttools.com.au/agent/{}", "method": "status", "found": 200, "missing": 404},
    "AgentSoftware": {"url": "https://www.agentsoftware.com.au/agent/{}", "method": "status", "found": 200, "missing": 404},
    "AgentApps": {"url": "https://www.agentapps.com.au/agent/{}", "method": "status", "found": 200, "missing": 404},
    "AgentMobile": {"url": "https://www.agentmobile.com.au/agent/{}", "method": "status", "found": 200, "missing": 404},
    "AgentWeb": {"url": "https://www.agentweb.com.au/agent/{}", "method": "status", "found": 200, "missing": 404},
    "AgentPortal": {"url": "https://www.agentportal.com.au/agent/{}", "method": "status", "found": 200, "missing": 404},
    "AgentDashboard": {"url": "https://www.agentdashboard.com.au/agent/{}", "method": "status", "found": 200, "missing": 404},
    "AgentControl": {"url": "https://www.agentcontrol.com.au/agent/{}", "method": "status", "found": 200, "missing": 404},
    "AgentManager": {"url": "https://www.agentmanager.com.au/agent/{}", "method": "status", "found": 200, "missing": 404},
    "AgentAdmin": {"url": "https://www.agentadmin.com.au/agent/{}", "method": "status", "found": 200, "missing": 404},
    "AgentSuper": {"url": "https://www.agentsuper.com.au/agent/{}", "method": "status", "found": 200, "missing": 404},
    "AgentMaster": {"url": "https://www.agentmaster.com.au/agent/{}", "method": "status", "found": 200, "missing": 404},
    "AgentPro": {"url": "https://www.agentpro.com.au/agent/{}", "method": "status", "found": 200, "missing": 404},
    "AgentElite": {"url": "https://www.agentelite.com.au/agent/{}", "method": "status", "found": 200, "missing": 404},
    "AgentPremium": {"url": "https://www.agentpremium.com.au/agent/{}", "method": "status", "found": 200, "missing": 404},
    "AgentVIP": {"url": "https://www.agentvip.com.au/agent/{}", "method": "status", "found": 200, "missing": 404},
    "AgentGold": {"url": "https://www.agentgold.com.au/agent/{}", "method": "status", "found": 200, "missing": 404},
    "AgentPlatinum": {"url": "https://www.agentplatinum.com.au/agent/{}", "method": "status", "found": 200, "missing": 404},
    "AgentDiamond": {"url": "https://www.agentdiamond.com.au/agent/{}", "method": "status", "found": 200, "missing": 404},
    "AgentSilver": {"url": "https://www.agentsilver.com.au/agent/{}", "method": "status", "found": 200, "missing": 404},
    "AgentBronze": {"url": "https://www.agentbronze.com.au/agent/{}", "method": "status", "found": 200, "missing": 404},
    "AgentCopper": {"url": "https://www.agentcopper.com.au/agent/{}", "method": "status", "found": 200, "missing": 404},
    "AgentIron": {"url": "https://www.agentiron.com.au/agent/{}", "method": "status", "found": 200, "missing": 404},
    "AgentSteel": {"url": "https://www.agentsteel.com.au/agent/{}", "method": "status", "found": 200, "missing": 404},
    "AgentTitanium": {"url": "https://www.agenttitanium.com.au/agent/{}", "method": "status", "found": 200, "missing": 404},
    "AgentCarbon": {"url": "https://www.agentcarbon.com.au/agent/{}", "method": "status", "found": 200, "missing": 404},
    "AgentNeon": {"url": "https://www.agentneon.com.au/agent/{}", "method": "status", "found": 200, "missing": 404},
    "AgentArgon": {"url": "https://www.agentargon.com.au/agent/{}", "method": "status", "found": 200, "missing": 404},
    "AgentKrypton": {"url": "https://www.agentkrypton.com.au/agent/{}", "method": "status", "found": 200, "missing": 404},
    "AgentXenon": {"url": "https://www.agentxenon.com.au/agent/{}", "method": "status", "found": 200, "missing": 404},
    "AgentRadon": {"url": "https://www.agentradon.com.au/agent/{}", "method": "status", "found": 200, "missing": 404},
    "AgentOganesson": {"url": "https://www.agentoganesson.com.au/agent/{}", "method": "status", "found": 200, "missing": 404},
}
class PySherlock:
    def __init__(self, usernames: List[str], sites: Optional[List[str]], threads: int, timeout: float, output: Optional[str], verbose: bool, proxy: Optional[str], csv: bool, nsfw: bool, print_all: bool):
        self.usernames = usernames
        self.sites = sites
        self.threads = threads
        self.timeout = timeout
        self.output = output
        self.verbose = verbose
        self.proxy = proxy
        self.csv = csv
        self.nsfw = nsfw
        self.print_all = print_all
        self.results: Dict[str, List[Dict]] = {}
        self.client = httpx.AsyncClient(http2=True, timeout=httpx.Timeout(timeout), limits=httpx.Limits(max_keepalive_connections=50, max_connections=100), proxy=proxy, follow_redirects=True)
    async def __aenter__(self):
        return self
    async def __aexit__(self, exc_type, exc, tb):
        await self.client.aclose()
    def banner(self):
        console.print("[bold #0e6b0e]PySherlock v1.0 - Username OSINT Hunter[/bold #0e6b0e]")
        console.print(f"[cyan]Targets: {', '.join(self.usernames)}[/cyan]")
        console.print(f"[cyan]Sites: {len(self.get_sites())}[/cyan]")
        console.print("")
    def get_sites(self) -> Dict[str, dict]:
        if self.sites:
            return {k: v for k, v in SITES.items() if k.lower() in [s.lower() for s in self.sites]}
        return SITES
    async def check_site(self, username: str, name: str, info: dict) -> Optional[dict]:
        url = info["url"].format(username)
        try:
            r = await self.client.get(url)
            status = r.status_code
            if info["method"] == "status":
                if status == info["found"]:
                    return {"username": username, "site": name, "url": url, "status": status, "exists": True}
                elif status == info.get("missing", 404):
                    if self.print_all:
                        return {"username": username, "site": name, "url": url, "status": status, "exists": False}
            elif info["method"] == "text":
                text = r.text
                if info.get("found_text") and info["found_text"] in text:
                    return {"username": username, "site": name, "url": url, "status": status, "exists": True}
                if info.get("missing_text") and info["missing_text"] in text:
                    if self.print_all:
                        return {"username": username, "site": name, "url": url, "status": status, "exists": False}
        except Exception:
            pass
        return None
    async def run(self):
        self.banner()
        sites = self.get_sites()
        total = len(self.usernames) * len(sites)
        found_total = 0
        from tqdm import tqdm
        pbar = tqdm(total=total, unit="checks", desc="sherlock", ncols=80)
        sem = asyncio.Semaphore(self.threads)
        for username in self.usernames:
            self.results[username] = []
            tasks = []
            for name, info in sites.items():
                tasks.append(self._check_wrapped(username, name, info, sem, pbar))
            results = await asyncio.gather(*tasks)
            for res in results:
                if res:
                    self.results[username].append(res)
                    if res["exists"]:
                        found_total += 1
                        console.print(f"[green][+] {res['site']}: {res['url']}[/green]")
                    elif self.print_all:
                        console.print(f"[dim][-] {res['site']}: not found[/dim]")
        pbar.close()
        console.print(f"\n[bold #0e6b0e]Done. Found {found_total} profile(s).[/bold #0e6b0e]")
        self.save()
    async def _check_wrapped(self, username: str, name: str, info: dict, sem: asyncio.Semaphore, pbar: tqdm):
        async with sem:
            res = await self.check_site(username, name, info)
            pbar.update(1)
            return res
    def save(self):
        if not self.output:
            return
        ext = os.path.splitext(self.output)[1].lower()
        try:
            if ext == ".json":
                with open(self.output, "w") as f:
                    json.dump(self.results, f, indent=2)
            elif ext == ".csv" or self.csv:
                import csv
                path = self.output if self.output else "sherlock.csv"
                with open(path, "w", newline="") as f:
                    writer = csv.writer(f)
                    writer.writerow(["username", "site", "url", "exists"])
                    for username, results in self.results.items():
                        for r in results:
                            writer.writerow([r["username"], r["site"], r["url"], r["exists"]])
            else:
                with open(self.output, "w") as f:
                    for username, results in self.results.items():
                        f.write(f"{username}\n")
                        for r in results:
                            status = "FOUND" if r["exists"] else "not found"
                            f.write(f"  [{status}] {r['site']}: {r['url']}\n")
            console.print(f"[green][+] Saved to {self.output}[/green]")
        except Exception as e:
            console.print(f"[red][!] Save failed: {e}[/red]")
@click.command()
@click.argument("usernames", nargs=-1, required=True)
@click.option("--site", multiple=True, help="Specific sites to check")
@click.option("--threads", default=30, help="Concurrent requests")
@click.option("--timeout", default=10.0, help="Request timeout")
@click.option("-o", "--output", help="Output file")
@click.option("-v", "--verbose", is_flag=True, help="Verbose")
@click.option("--proxy", help="Proxy URL")
@click.option("--csv", is_flag=True, help="CSV output")
@click.option("--nsfw", is_flag=True, help="Include NSFW sites")
@click.option("--print-all", is_flag=True, help="Print all results including not found")
def cli(usernames, site, threads, timeout, output, verbose, proxy, csv, nsfw, print_all):
    sherlock = PySherlock(list(usernames), list(site) if site else None, threads, timeout, output, verbose, proxy, csv, nsfw, print_all)
    asyncio.run(sherlock.run())
if __name__ == "__main__":
    cli()
