import urllib
import pandas as pd
from requests_html import HTMLSession
import requests
from bs4 import BeautifulSoup
from datetime import datetime
import tldextract

URL = "URL"

HASH = "Hash"

OUTPUT_XLSX = "output.xlsx"

KEYWORDS_COUNT = "Keywords Count"

BAD_TITLE = "403 Forbidden"


class SecurityIncidents:
    """
    System that finds incidents of SaaS vendors new incidents.
    The system receives a list of vendors , scan the internet and provide a list of potential articles
    of such security breaches.

    """

    def __init__(self):
        """
    Init a SecurityIncidents object
    """
        self.keywords = set(["exploit", "breach", "vulnerability", "cyber-attack"])
        self.seen_urls = dict()
        print("Initializing the system...")

    def __get_source(self, url):
        """
        Return the source code for the provided URL.
        :param url (string): URL of the page to scrape.
        :return: HTTP response object from requests_html.
        """
        try:
            session = HTMLSession()
            response = session.get(url)
            return response

        except requests.exceptions.RequestException as e:
            print(e)

    def __scrape_google(self, query):
        """

        :param query: Query for goggle search
        :return: list of relevant links
        """
        try:
            query = urllib.parse.quote_plus(query)
            response = self.__get_source("https://www.google.co.il/search?q=" + query)
            links = list(response.html.absolute_links)

            return links
        except Exception as e:
            return []

    def add_seen_urls(self, path):
        """

        :param path: to the excel with already scanned urls. The excel must contain URL column
        Insert the urls to the system
        """
        print("Starts to read from excel")
        df = pd.read_excel(path)
        if HASH in df.columns:
            self.__add_urls_to_seen_from_df(df)
        for url in df[URL]:
            hash_url, _ = self.__create_hash_and_soup_obj(url)
            self.__add_hash_to_url(hash_url, url)

    def __add_urls_to_seen_from_df(self, df):
        """

        :param df: dataframe of urls
        Parse them into the already seen urls, in order to avoid returning them again
        """
        if not df.empty:
            for url in df[URL]:
                series = df.loc[df[URL] == url][HASH]
                hash_url = series.item()
                self.__add_hash_to_url(hash_url, url)

    def __add_hash_to_url(self, hash_url, url):
        """

        :param hash_url: value for dict
        :param url: key for dict
        insert the url to the seen_urls
        """
        self.seen_urls[url] = hash_url

    def __parse_links(self, links, d, vendor, keyword):
        """

        :param links: lists of links
        :param d: dictionary to add the links to it
        :param vendor: vendor name
        :param keyword: relevent keyword
        """
        print(f"Starts to parse google links for {vendor} {keyword}")
        google_domains = ('https://www.google.',
                          'https://google.',
                          'https://webcache.googleusercontent.',
                          'http://webcache.googleusercontent.',
                          'https://policies.google.',
                          'https://support.google.',
                          'https://maps.google.',
                          'https://translate.google.'
                          )
        for url in links:
            if url.startswith(google_domains):
                continue
            hash_url, soup = self.__create_hash_and_soup_obj(url)
            if hash_url is None and soup is None:
                continue
            if url in self.seen_urls and self.seen_urls[url] == hash_url:
                continue

            else:
                if url in d:
                    d[url]["Vendor"].add(vendor)
                    d[url]["Keywords"].add(keyword)
                    d[url]["Keywords Count"] += 1
                else:
                    ext = tldextract.extract(url)
                    title = ""
                    for title_ob in soup.find_all('title'):
                        title += title_ob.get_text()
                    if title == BAD_TITLE:
                        title = ""
                    d[url] = {URL: url, "Domain": ext.domain, "Vendor": {vendor}, "Keywords": {keyword},
                              KEYWORDS_COUNT: 1
                        , "Found on": datetime.now(), "Title": title, HASH: hash_url}

    def __create_hash_and_soup_obj(self, url):
        """

        :param url:
        :return: the soap object of this url, and the hash of its content
        """
        try:
            page = requests.get(url)
            if page.status_code == 404:
                return None, None
            soup = BeautifulSoup(page.text, "html.parser")
            hash_url = hash(soup.content)
            return hash_url, soup
        except Exception as e:
            return None, None

    def get_potential_urls(self, vendors, to_excel=False):
        """

        :param vendors: list of vendors to scan for new articles
        :param to_excel: do you want to export excel for the output?
        :return: dataframe if to_excel is False, otherwise None
        """
        data = dict()
        index = -1
        for vendor in vendors:
            for keyword in self.keywords:
                index += 1
                query = f"{vendor} {keyword}"
                self.__parse_links(self.__scrape_google(query), data, vendor, keyword)
                print(f"Finished {query}")
        df = pd.DataFrame.from_dict(data, orient='index')
        df.reset_index(drop=True, inplace=True)
        self.__add_urls_to_seen_from_df(df)
        if not df.empty:
            df = df.sort_values([KEYWORDS_COUNT], ascending=False)
        if to_excel:
            df.to_excel(OUTPUT_XLSX)
            print(f"Table of potential new incidents exported to {OUTPUT_XLSX}")
        else:
            return df
