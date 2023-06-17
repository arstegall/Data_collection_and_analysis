import collections
import copy
import datetime
import json
import sys
from typing import List

import numpy as np
import pandas as pd
import requests
from bs4 import BeautifulSoup
from dateutil.relativedelta import relativedelta
from matplotlib import pyplot as plt
from tabulate import tabulate


def save_to_file(data, file_name):
    """
    Funkcija koju pozivamo kada podatke zelimo trajno pohraniti u datoteku
    Args:
        data (str): podaci za zapisati u datoteku
        file_name (str): ime datooteke u koju ce se zapisati podaci

    Returns:
        None
    """
    try:
        with open(file_name, "w") as f:
            f.write(data)
    except Exception as err:
        print(f"Greska kod pisanja: {err}")


def extract_news_from_last_year(category):
    """
    U ovoj funkciji imami logiku koja pronalazi sve clanke na index.hr stranice u proteklih dana.
    Funkcija radi na nacin da koristi trazilizu index portala, trazilicu ispuni sa imenom kategorije
    kao npr. "vijesti" te se koristi order_by opcija za sortiranje clanaka od najnovijeg prema najstarijem.
    Iteriramo kroz rezultate i izvlacimo rezultate do trenutka kada naidemo na clanak koji je stariji od
    godine dana. Za parsiranje stranice koristi se BeautifulSoup. Nakon sto smo iterirali kroz sve clanke
    rezultate spremamo u novu datoteku kako bi bili dostupni za kasniju analizu
    Notes:
        Ova funkcija se moze izvrsavati jako dugo vremena zbog mnogobrojnih zahtjeva prema portalu,
        nase zabiljeno vrijeme je cca 5 sati!
    Args:
        category (str): kategorija koja se pretrazuje i za koju extractamo clanke sa portala

    Returns:
        titles (list): lista svih pronadenih naslova za danu kategoriju

    """
    year_ago = datetime.datetime.now() - relativedelta(years=1)
    year_ago = year_ago.strftime("%d.%m.%Y.")
    i = 1
    end = False
    titles = []
    saved_files = 0
    check = 0
    check_2 = 0
    while True:
        try:
            url = f'https://www.index.hr/trazi.aspx?take=15&page={i}&orderby=latest&upit={category}'
            if check_2 == 100:
                print(f"Na stranici: {url}")
                check_2 = 0
            stranica = requests.get(url=url)
            soup = BeautifulSoup(stranica.content, 'lxml')
            for item in soup.find_all('div', class_='publish-date'):
                check += 1
                if check == 100:
                    print(item.get_text())
                    check = 0
                item = item.get_text()
                item = item.strip()
                # if item == year_ago:
                if item == "30.11.2021.":
                    end = True

            if end:
                break

            news = soup.find_all('a', class_='vijesti-text-hover scale-img-hover')
            # neke kategorije mogu biti drukcije kao npr. sport
            if category == "sport":
                news = soup.find_all('a', class_='sport-text-hover scale-img-hover')
            elif category == "magazin":
                news = soup.find_all('a', class_='magazin-text-hover scale-img-hover')
            if not news:
                break
            for item in news:
                titles.append(item['href'])
        except Exception as err:
            print(f"Greska na stranici {i}.\nGreska: {err}")
            i += 1
            continue
        """
        if len(titles) >= 300:
            print(f"Writing to file: news_{saved_files}.json")
            save_to_file(json.dumps(titles), file_name=f"news_{saved_files}.json")
            saved_files += 1
            titles = []
        """
        i += 1
    print("Saving")
    save_to_file(json.dumps(titles), file_name=f"{category}_links.json")
    return titles


def remove_last_h3_item(html: str):
    """
    Funkcija sa kojim prociscavamo preuzete clanke.
    Konkretno uklanjamo h3 html oznake.
    Args:
        html (str): html string koji prociscavamo od h3 oznaka

    Returns:
        clean_html (str): procisceni html string
    """
    split_by_h3 = html.split("<h3")
    split_by_h3.pop()
    clean_html = "<h3".join(split_by_h3)

    return clean_html


def find_category(url: str):
    """
    Funkcija pomocu koj iz URL-a clanka izdvajamo kategoriju u koju clanak pripada
    (kategorija clanka je navedena u URL-u)
    Args:
        url (str): URL clanka iz kojeg citamo kategoriju u koju clanak pripada

    Returns:
        category (str): detektirana kategorija u koju pripada clanak uz pripadajuci URL
    """
    split_url = url.split("/")

    category = "Unknown"
    for i, item in enumerate(split_url):
        if item == "clanak":
            category = split_url[i - 1]
        continue

    return category


def find_title(soup):
    """
    Funkcija pomocu koje pronalazimo naslov clanka sluzeci se title html oznakom u html-u clanka.
    Args:
        soup: bs objekt koji sadrzava cijeloviti html clanka

    Returns:
        title (str): detektirani naslov clanka
    """
    title = str(soup.find("title"))
    title = title.replace("<title>", "")
    title = title.replace("</title>", "")
    title = title.replace(" - Index.hr", "")

    return title


def find_date_and_author(info):
    """
    Funkcija pomocu koje pronalazimo autora i datum clanka.
    Ova funkcija ucitava html clanka te u javascript skriptama dostupnima u html-u
    pronalazi podatke o autoru i datumu objavljivanja clanka.
    Takoder prilagodava datum u zeljeni format

    Args:
        info: bs objekt koji sadrzava potrebne html podatke

    Returns:
        date, author_full_name (str, str): datum objave clanka te autor clanka
    """
    date, author_full_name = None, None
    for i in info:
        if "varauthors=" in i:
            author = i.split("=")[-1]
            author = author.replace("]).map(function(m){", "")
            author = author.replace("([", "")
            author = json.loads(author)
            author_full_name = f"{author['firstName']} {author['lastName']}"
        if "varpublishDate=" in i:
            date = i.split("=")[-1]
            date = date.replace("'", "")
            date = date.replace(";", "")

    return date, author_full_name


def find_keywords(info):
    """
    Funkcija pomocu koje iz html-a izvlacimo kljucne rijeci.
    Slicno find_date_and_author funkciji ova funkcija trazi javascript kod
    unutar htmla koji sadrzi kljucne rijeci koje je naveo autor clanka
    Args:
        info:  bs objekt koji sadrzava potrebne html podatke

    Returns:
        found_keywords (list): pronadene kljucne rijeci clanka
    """
    keywords = []
    for i in info:
        if "keywords" in i:
            keywords = i.split("=")[-1]
            keywords = keywords.replace("]).map(function(m){", "")
            keywords = keywords.replace("([", "")
            keywords = f"[{keywords}]"
            keywords = json.loads(keywords)

    found_keywords = []
    for keyword in keywords:
        found_keywords.append(keyword.get("keyWord"))

    return found_keywords


def find_text_in_html_format(soup):
    """
    Funkcija koja pretvara bs objekt u string koji spremamo kao tekst clanka
    Args:
        soup: bs objekt sa html-om clanka

    Returns:
        full_text_in_html (str): string generiran iz bs objekta
    """
    full_text_in_html = ""
    last_tag = None
    for item in soup.find_all(tagovi):
        if item.name == "h3" and last_tag == "h3":
            # preskcaemo, ako je vise naslova zaredom to su onda predlozeni clanci
            last_tag = item.name
            continue
        last_tag = item.name
        item = str(item)
        full_text_in_html += item

    full_text_in_html = remove_last_h3_item(full_text_in_html)
    return full_text_in_html


def remove_html_tags(html: str, tags: List[str]):
    """
    Ova funkcija ce pretvarati clanke iz html formata u obican string.
    (HTML oznake biti ce izbrisane).
    Notes:
        Koristenjem ove funkcije biti ce teze prepoznati podnaslove unutar clanka
    Args:
        html (str): html string clanka
        tags (list): html oznake koje zelimo ukloniti iz html-a

    Returns:
        html (str): string sa uklojenim html tagovima
    """
    for tag in tags:
        html = html.replace(f"<{tag}>", "")
        html = html.replace(f"</{tag}>", "")

    return html


def load_all_links(categories_list, links_suffix="_links"):
    """
    Funkcija koja iz vec spremljene datoteke ucitava sve spremljene linkove clanaka.
    Pretpostavka je da za svaku kategoriju postoji zasebna datoteka te se ucitava kategorija po kategorija.
    Args:
        categories_list (str): lista kategorija za koju zelimo ucitati linkove iz datoteke
        links_suffix (str): sufiks koji smo zadali za datoteku koja sadrzi iskljucivo linkove na clanke
        (ne i sam sadrzak clanaka)

    Returns:
        links (list): lista koja sazdrava sve pohranjene linkove u datotekama za dane kategorije
    """
    links = []
    for category in categories_list:
        try:
            with open(f"{category}{links_suffix}.json", "r") as f:
                data = json.loads(f.read())
                links += data
        except Exception as err:
            print(err)
            continue

    return links


def load_all_articles(categories_list, links_suffix="_extracted_data"):
    """
    Funkcija koja iz vec spremljenih datoteka ucitava sve clanke tj sadrzaj clanaka.
    Pretpostavka je da za svaku kategoriju postoji zasebna datoteka te se ucitava kategorija po kategorija.

    Zbog potencialnog velikog broja clanaka datoteke mogu biti relativno velike sto ce utjecati na performanse
    tj. brzinu rada ovog koda.

    Args:
        categories_list (str): lista kategorija za koju zelimo ucitati sadrzaj clanaka iz datoteke
        links_suffix: sufiks koji smo zadali za datoteku koja sadrzi sadrzaje clanaka

    Returns:
        articles (list): lista sa svim pohranjemim clancima i njihovim sadrzajem

    """
    articles = []
    if isinstance(categories_list, str):
        categories_list = [categories_list]

    for category in categories_list:
        try:
            with open(f"{category}{links_suffix}.json", "r") as f:
                data = json.loads(f.read())
                articles += data
        except Exception as err:
            print(err)
            continue

    return articles


def extract_corona_articles(articles):
    """
    Funkcija pomocu koje detektiramo sve clanke vezane uz korona virus tematiku te takve clanke izvlacimo za daljnu obradu.
    za kasniju obradu. Korona clanci prepoznati su na nacin da pretrazujemo tekst naslova clanka,
    tekst samog sadrzaja clanka i spomenute kljucne rijeci u clanku te s obzirom na predefiniranu listu rijeci
    koje se asociraju sa korona virusom odlucujemo radi li se o clanku koji je vezan za korona virus ili ne
    Args:
        articles (list): lista svih clanaka koji su pronadeni za period od zadnjih godinu dana

    Returns:
        corona_articles (list): lista svih clanaka koji su detekirani da sadrze tekst koji se dotice teme korona virusa

    """
    corona_articles = []
    corona_keywords = ["sars-cov-2", "covid-19", "covid", "corona", "korona", "koronavirus", "korona-virus", "virus",
                       "epidemija", "pandemija", "samoizolacija", "izolacija", "novozarazen", "koronakriza",
                       "propusnica", "cjepivo", "cijepljenje", "lockdown", "who", "stozer civilne zastite", "stozer",
                       "omikron", "omicron", "mjere", "maske", "delta"]
    for article in articles:
        is_stored = False
        for keyword in corona_keywords:
            if keyword in article["naslov"].lower():
                corona_articles.append(article)
                is_stored = True
                continue
            if keyword in article["tekst_clanka"].lower():
                corona_articles.append(article)
                is_stored = True
                continue
            for article_keyword in article["keywords"]:
                if keyword in article_keyword.lower():
                    corona_articles.append(article)
                    is_stored = True
        if is_stored:
            continue

    return corona_articles


def extract_vaccination_articles(corona_articles):
    """
    Funkcija pomocu koje detektiramo sve clanke vezane uz podtemu cijepljenja protiv korona virusa
    te takve clanke izvlacimo za daljnu obradu.
    Clanci o cijepljenju prepoznati su na nacin da pretrazujemo tekst naslova clanka,
    tekst samog sadrzaja clanka i spomenute kljucne rijeci u clanku te s obzirom na predefiniranu listu rijeci
    koje asociraju na cijepljenjem protiv korona virusa odlucujemo radi li se o clanku koji je vezan
    za cijepljenje protiv virusa ili ne
    Args:
        corona_articles (list): lista svih clanaka koji su pronadeni na temu korona virusa za period od zadnjih godinu dana

    Returns:
        vaccination_keywords (list): lista svih clanaka koji su detekirani da sadrze tekst koji se dotice teme
        cijepljenja protiv korona virusa

    """
    vaccination_articles = []
    vaccination_keywords = ["cijepljenje", "cjepivo", "procijepljenost", "biontech", "pfizer", "sputnik", "astrazeneca",
                            "zeneca", "moderna", "johnson & johnson", "johnson&johnson", "novavax"]
    for article in corona_articles:
        is_stored = False
        for keyword in vaccination_keywords:
            if keyword in article["naslov"].lower():
                vaccination_articles.append(article)
                is_stored = True
                continue
            if keyword in article["tekst_clanka"].lower():
                vaccination_articles.append(article)
                is_stored = True
                continue
            for article_keyword in article["keywords"]:
                if keyword in article_keyword.lower():
                    vaccination_articles.append(article)
                    is_stored = True
        if is_stored:
            continue

    return vaccination_articles


def extract_isolation_articles(corona_articles):
    """
    Funkcija pomocu koje detektiramo sve clanke vezane uz podtemu samoizolacije
    te takve clanke izvlacimo za daljnu obradu.
    Clanci o samoizolaciji prepoznati su na nacin da pretrazujemo tekst naslova clanka,
    tekst samog sadrzaja clanka i spomenute kljucne rijeci u clanku te s obzirom na predefiniranu listu rijeci
    koje asociraju na samoizolaciju te odlucujemo radi li se o clanku koji je vezan
    za samoizolaciju ili ne
    Args:
        corona_articles (list): lista svih clanaka koji su pronadeni na temu korona virusa za period od zadnjih godinu dana

    Returns:
        isolation_articles (list): lista svih clanaka koji su detekirani da sadrze tekst koji se dotice teme
        samoizolacije

    """
    isolation_articles = []
    isolation_keywords = ["izolacija", "izolaciji", "samoizolacija", "samoizolaciji", "karantena", "izolirati",
                          "kucna izolacija", "ukucani"]
    for article in corona_articles:
        is_stored = False
        for keyword in isolation_keywords:
            if keyword in article["naslov"].lower():
                isolation_articles.append(article)
                is_stored = True
                continue
            if keyword in article["tekst_clanka"].lower():
                isolation_articles.append(article)
                is_stored = True
                continue
            for article_keyword in article["keywords"]:
                if keyword in article_keyword.lower():
                    isolation_articles.append(article)
                    is_stored = True
        if is_stored:
            continue

    return isolation_articles


def extract_symptoms_articles(corona_articles):
    """
    Funkcija pomocu koje detektiramo sve clanke vezane uz podtemu simptoma korona virusa
    te takve clanke izvlacimo za daljnu obradu.
    Clanci o simptomima korone prepoznati su na nacin da pretrazujemo tekst naslova clanka,
    tekst samog sadrzaja clanka i spomenute kljucne rijeci u clanku te s obzirom na predefiniranu listu rijeci
    koje asociraju na simptome korone te odlucujemo radi li se o clanku koji je vezan
    za simptome korone ili ne
    Args:
        corona_articles (list): lista svih clanaka koji su pronadeni na temu korona virusa za period od zadnjih godinu dana

    Returns:
        symptoms_articles (list): lista svih clanaka koji su detekirani da sadrze tekst koji se dotice teme
        simptoma korone

    """
    symptoms_articles = []
    symptoms_keywords = ["simptom", "simptomi", "kasalj", "nedostatak daha", "otezano disanje", "temperatura", "zimica",
                         "bolovi u misicima", "bolovi u tijelu", "povracanje", " glavobolja", "gubitak mirisa",
                         "gubitak okusa", "proljev", "umor", "konjuktivitis", "slabost"]
    for article in corona_articles:
        is_stored = False
        for keyword in symptoms_keywords:
            if keyword in article["naslov"].lower():
                symptoms_articles.append(article)
                is_stored = True
                continue
            if keyword in article["tekst_clanka"].lower():
                symptoms_articles.append(article)
                is_stored = True
                continue
            for article_keyword in article["keywords"]:
                if keyword in article_keyword.lower():
                    symptoms_articles.append(article)
                    is_stored = True
        if is_stored:
            continue

    return symptoms_articles


def remove_duplicated_dicts_from_list(items):
    """
    Pomocna funkcija kojom micemo duplikate iz dane liste
    Args:
        items (list): lista koju zelimo procistiti od duplikata

    Returns:
        items_without_duplicates (list): lista bez duplikata
    """
    fixed_items = []
    for i in items:
        fixed_items.append(json.dumps(i))

    fixed_items = list(set(fixed_items))

    items_without_duplicates = []
    for i in fixed_items:
        items_without_duplicates.append(json.loads(i))

    return items_without_duplicates


def generate_monthly_statistic(articles):
    """
    Funkcija koju koristimo za generiranje mjesecne statistike odnosno racunanje
    broja clanaka po mjesecima
    Args:
        articles (list): lista clanaka za koju zelimo provesti generiranje statistike po mjesecima

    Returns:
        month_statistic (dict): dict objekt koji sadrze sve mjesece (kao kljucevi dict objekta)
        te broj objavljenih clanaka za taj mjesec
    """
    month_statistic = {
        "01": 0,
        "02": 0,
        "03": 0,
        "04": 0,
        "05": 0,
        "06": 0,
        "07": 0,
        "08": 0,
        "09": 0,
        "10": 0,
        "11": 0,
        "12": 0,
        "unknown": 0
    }

    for article in articles:
        if article.get("datum"):
            datum = article["datum"].split("-")
            month = datum[1]

            try:
                month_statistic[month] += 1
            except KeyError:
                month_statistic["unknown"] += 1
        else:
            month_statistic["unknown"] += 1

    return month_statistic


def replace_croatian_chars(string):
    """
    Prilikom spremanja clanaka znakovi karakteristicni za hrvatsku abecedu su spremljeni kao
    unicode blok. Ova funkcija pretvara unicode blokove za hrvatska slova u najslicnija internacionalna slova
    (npr. Š->S...)
    Args:
        string (str): string u kojem zelimo pretvoriti unicode blokove u slova

    Returns:
        string (str): string bez unicode blokova
    """
    string = string.replace("\\u0107", "c")
    string = string.replace("\\u0106", "C")
    string = string.replace("\\u0110c", "c")
    string = string.replace("\\u0110d", "C")
    string = string.replace("\\u0110", "Dj")
    string = string.replace("\\u0111", "dj")
    string = string.replace("\\u0160", "S")
    string = string.replace("\\u0161", "s")
    string = string.replace("\\u017d", "Z")
    string = string.replace("\\u017e", "z")

    return string


if __name__ == "__main__":
    categories = ['vijesti', 'sport', 'magazin', 'plus', 'info']
    # load_all_links(categories)
    print(
        "Zelis li  pokrenuti prikupljanje svih clanaka u proteklih godinu dana (UPOZORENJE: Ovo moze trajati nekoliko sati!)")
    new_scan = input("Odgovori sa 'da' za prikaz, svaki drugi odgovor biti ce smatran negativnim: ")

    new_scan = new_scan.lower()
    if new_scan == "da":
        for category in categories:
            print(f"Kategorija: {category}")
            titles = extract_news_from_last_year(category)

            headers = {
                "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.131 Safari/537.36"}

            records = []
            check = 0
            for i, title in enumerate(titles):
                if i == 300:
                    print("....")
                url = f'https://index.hr{title}'

                try:
                    stranica = requests.get(url=url, headers=headers)
                    soup = BeautifulSoup(stranica.content, 'lxml')

                    tagovi = ['p', 'h3']

                    record = {}
                    record["naslov"] = find_title(soup)
                    record["kategorija"] = find_category(url)

                    info = soup.find_all(["script"])
                    # format info data from javascript like part of web page
                    info = str(info)
                    info = info.replace(" ", "")
                    info = info.split("\n")

                    date, author = find_date_and_author(soup)
                    record["datum"] = date
                    record["autor"] = author

                    full_text = find_text_in_html_format(soup)
                    # full_text = remove_html_tags(full_text, tags) # ako se zele maknuti HTML tagovi
                    record["tekst_clanka"] = full_text

                    keywords = find_keywords(info)
                    record["keywords"] = keywords

                    records.append(record)
                except Exception as err:
                    print(f"Greska za vijest: {url}.\nGreska: {err}")
                    continue
            print(f"Obradeno {len(records)} vijesti za kategoriju: {category}")
            save_to_file(json.dumps(records), file_name=f"{category}_extracted_data.json")

    all_articles = load_all_articles(categories, links_suffix="_new")

    corona_articles = extract_corona_articles(all_articles)
    corona_articles = remove_duplicated_dicts_from_list(corona_articles)

    vaccination_articles = extract_vaccination_articles(corona_articles)
    vaccination_articles = remove_duplicated_dicts_from_list(vaccination_articles)

    isolation_articles = extract_isolation_articles(corona_articles)
    isolation_articles = remove_duplicated_dicts_from_list(isolation_articles)

    symptoms_articles = extract_symptoms_articles(corona_articles)
    symptoms_articles = remove_duplicated_dicts_from_list(symptoms_articles)

    print(30 * "#")
    print("\tANALIZA\t")
    print(30 * "#")

    data = [
        ["Ukupno prikupljenih clanaka", len(all_articles)],
        ["Ukupno prikupljenih clanaka na temu korone", len(corona_articles)],
        ["Ukupno prikupljenih clanaka na podtemu cijepljenje", len(vaccination_articles)],
        ["Ukupno prikupljenih clanaka na podtemu samoizolacije: ", len(isolation_articles)],
        ["Ukupno prikupljenih clanaka na podtemu simptoma korone: ", len(symptoms_articles)]
    ]
    print(tabulate(data, tablefmt="grid"))

    print(30 * "#")
    print("\tANALIZA po kategorijama\t")
    print(30 * "#")

    vijesti, sport, magazin, plus, info = 0, 0, 0, 0, 0
    for article in all_articles:
        if article["kategorija"] == "vijesti":
            vijesti += 1
        elif article["kategorija"] == "sport":
            sport += 1
        elif article["kategorija"] == "magazin":
            magazin += 1
        elif article["kategorija"] == "plus":
            plus += 1
        elif article["kategorija"] == "info":
            info += 1

    vijesti_corona, sport_corona, magazin_corona, plus_corona, info_corona = 0, 0, 0, 0, 0
    for article in corona_articles:
        if article["kategorija"] == "vijesti":
            vijesti_corona += 1
        elif article["kategorija"] == "sport":
            sport_corona += 1
        elif article["kategorija"] == "magazin":
            magazin_corona += 1
        elif article["kategorija"] == "plus":
            plus_corona += 1
        elif article["kategorija"] == "info":
            info_corona += 1

    data = [
        ["Broj objava u kategoriji Vijesti", vijesti],
        ["Broj objava u kategoriji Sport", sport],
        ["Broj objava u kategoriji Magazin", magazin],
        ["Broj objava u kategoriji Plus", plus],
        ["Broj objava u kategoriji Info", info],
        ["Korona virus u kategoriji Vijesti", vijesti_corona],
        ["Korona virus u kategoriji Sport", sport_corona],
        ["Korona virus u kategoriji Magazin", magazin_corona],
        ["Korona virus u kategoriji Plus", plus_corona],
        ["Korona virus u kategoriji Info", info_corona],
    ]
    print(tabulate(data, tablefmt="grid"))

    print(30 * "#")
    print("\tBroj objava po mjesecima\t")
    print(30 * "#")

    month_statistic_all = generate_monthly_statistic(all_articles)
    month_statistic_corona = generate_monthly_statistic(corona_articles)
    month_statistic_vaccination = generate_monthly_statistic(vaccination_articles)
    month_statistic_isolation = generate_monthly_statistic(isolation_articles)
    month_statistic_symptoms = generate_monthly_statistic(symptoms_articles)

    data = [
        ["Broj objava u Sijecanj", month_statistic_all["01"]],
        ["Broj objava u Veljaca", month_statistic_all["02"]],
        ["Broj objava u Ozujak", month_statistic_all["03"]],
        ["Broj objava u Travanj", month_statistic_all["04"]],
        ["Broj objava u Svibanj", month_statistic_all["05"]],
        ["Broj objava u Lipanj", month_statistic_all["06"]],
        ["Broj objava u Srpanj", month_statistic_all["07"]],
        ["Broj objava u Kolovoz", month_statistic_all["08"]],
        ["Broj objava u Rujan", month_statistic_all["09"]],
        ["Broj objava u Listopad", month_statistic_all["10"]],
        ["Broj objava u Studeni", month_statistic_all["11"]],
        ["Broj objava u Prosinac", month_statistic_all["12"]],
        ["Nepoznato", month_statistic_all["unknown"]],
    ]
    print(tabulate(data, tablefmt="grid"))

    # generiranje podataka po mjesecima za kasniju vizualizaciju

    print(
        "Zelis li prikazati tablicu objava po danu (UPOZORENJE: Zbog velicine tablice podaci ce mozda biti tesko citljivi)")
    daily_view = input("Odgovori sa 'da' za prikaz, svaki drugi odgovor biti ce smatran negativnim: ")
    daily_view = daily_view.lower()
    data = []
    if daily_view == 'da':
        print(30 * "#")
        print("\tBroj objava po danima\t")
        print(30 * "#")

        start_date = datetime.date(2021, 11, 1)
        end_date = datetime.date(2022, 12, 1)
        delta = datetime.timedelta(days=1)
        while start_date <= end_date:
            no_articles = 0
            no_corona_articles = 0
            no_vaccination_articles = 0
            no_isolation_articles = 0
            no_symptoms_articles = 0
            datum = start_date.strftime("%Y-%m-%d")
            for article in all_articles:
                if article["datum"] == datum:
                    no_articles += 1
            for article in corona_articles:
                if article["datum"] == datum:
                    no_corona_articles += 1
            for article in vaccination_articles:
                if article["datum"] == datum:
                    no_vaccination_articles += 1
            for article in isolation_articles:
                if article["datum"] == datum:
                    no_isolation_articles += 1
            for article in symptoms_articles:
                if article["datum"] == datum:
                    no_symptoms_articles += 1

            data.append([f"Broj objava na dan {datum}", no_articles])
            data.append([f"Broj objava na temu korona na dan {datum}", no_articles])
            data.append([f"Broj objava na podtemu cijepljenje na dan {datum}", no_vaccination_articles])
            data.append([f"Broj objava na podtemu samoizolacija na dan {datum}", no_isolation_articles])
            data.append([f"Broj objava na podtemu korona simptomi na dan {datum}", no_symptoms_articles])
            start_date += delta
    print(tabulate(data, tablefmt="grid"))

    plt.title("Broj objava po svim kategorijama po mjesecima", size=11)
    data = month_statistic_all
    mjeseci = list(data.keys())
    objave = list(data.values())
    plt.bar(range(len(data)), objave, tick_label=mjeseci)
    plt.xlabel("Mjesec")
    plt.ylabel("Broj objava")
    plt.xticks(size=8.5)
    plt.yticks(size=11)
    plt.show()

    y = [len(corona_articles), len(all_articles) - len(corona_articles)]
    mylabels = ["Korona objave", "Sve ostale objave"]
    plt.title("Omjer korona objava i svih ostalih objava")
    plt.pie(y, labels=mylabels, autopct='%1.2f%%')
    plt.show()

    month_statistic_corona.values()

    labels = list(month_statistic_all.keys())
    corona_news = list(month_statistic_corona.values())
    all_news = list(month_statistic_all.values())
    width = 0.35
    fig, ax = plt.subplots()
    ax.bar(labels, all_news, width, label='Sve vijesti')
    ax.bar(labels, corona_news, width, label='Korona vijesti')
    ax.set_ylabel('Broj objava')
    ax.set_xlabel('Mjesec')
    ax.legend()
    plt.title("Udio korona objava u ukupnom broju objava po mjesecima", size=12)
    plt.show()

    y = [vijesti_corona, sport_corona, magazin_corona, plus_corona, info_corona]
    mylabels = ["Vijesti", "Sport", "Magazin", "Plus", "Info"]
    plt.title("Omjer objava na temu korone po raznim kategorijama portala")
    plt.pie(y, startangle=30, autopct='%1.1f%%', radius=1.2)
    plt.legend(mylabels, loc='best', bbox_to_anchor=(-0.1, 1.), fontsize=12)
    plt.show()

    labels = list(month_statistic_all.keys())
    data = []
    for i in month_statistic_all.keys():
        temp = [month_statistic_vaccination[i], month_statistic_isolation[i], month_statistic_symptoms[i]]
        data.append(temp)
    data = np.array(data)
    category_names = ["Cijepljnje", "Samoizolacija", "Simptomi"]
    data_cum = data.cumsum(axis=1)

    fig, ax = plt.subplots(figsize=(12, 6))
    ax.set_title("Usporedba broja clanaka na temu cijepljenje-samoizolacija-simptomi po mjesecima")
    ax.invert_yaxis()
    ax.xaxis.set_visible(True)
    ax.set_xlim(0, np.sum(data, axis=1).max())

    for i, colname in enumerate(category_names):
        widths = data[:, i]
        starts = data_cum[:, i] - widths
        rects = ax.barh(labels, widths, left=starts, height=0.5, label=colname)

    ax.legend(bbox_to_anchor=(0, 1), loc=4, fontsize='10')

    stopwords = {'nije', 'te', 'koje', 'kao', 'do', 'biti', 'nakon', 'smo', 'vi', 'sve', 'koja', 'zbog', 'on', 'kod',
                 'oni', 'tu', 'ona', 'pod', 'sam', 'bio', 'samo', 'bilo', 'li', 'kada', 'uz', 'mu', 'tome', 'po',
                 'prema', 'oko', 'ako', 'ima', 'ga', 'nego', 'i', 'no', 'ili', 'ali', 'stoga', 'zato', 'jer', 'je', 'u',
                 'da', 'na', 'se', 'su', 'za', 'od', 's', 'koji', 'to', 'o', 'a', 'ne', 'rekao', 'bi', 'tako', 'kako',
                 'iz', 'target=\_blank\>&gt;&gt;', 'null', 'tekst_clanka', 'keywords', 'autor', 'naslov', 'kategorija',
                 'datum', 'href', 'p', 'h3', 'target', '{naslov', 'ce', 'sto', 'vise', 'jos', 'moze', 'vec', 'nisu',
                 'sta', 'sa', 'mi', 'posto', 'pa', 'bila', 'sada', 'dok', 'ni', 'ih', 'kad', 'moje', 'svoje', 'tvoje',
                 'bez', 'toga', '-', '<a'}

    a = json.dumps(corona_articles)
    a = replace_croatian_chars(a)
    # Radimo popis rijeci koje se pronadu i broj pojavljivanja
    wordcount = {}
    # Micanje specijalnih simbola iz teksta
    for word in a.lower().split():
        word = word.replace(".", "")
        word = word.replace(",", "")
        word = word.replace(":", "")
        word = word.replace("\"", "")
        word = word.replace("!", "")
        word = word.replace("*", "")
        if word not in stopwords:
            if word not in wordcount:
                wordcount[word] = 1
            else:
                wordcount[word] += 1
    # Ispis 25 rijeci koje se najcesce ponavljaju
    n_print = 25
    print("\nNajcescih {} koristenih rijeci u clancima su:\n".format(n_print))
    word_counter = collections.Counter(wordcount)
    for word, count in word_counter.most_common(n_print):
        print(word, ": ", count)

    # Crtanje bar charta
    lst = word_counter.most_common(n_print)
    df = pd.DataFrame(lst, columns=['Rijec', 'Broj ponavljanja'])
    df.plot.bar(x='Rijec', y='Broj ponavljanja')
