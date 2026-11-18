# SPDX-License-Identifier: AGPL-3.0-only
"""Common Turkish given names for the optional ``person_name`` detector (off by default).

The detector masks "<given name> <Capitalised surname>" only; a given name alone is left alone, because many of
these are also ordinary words (Deniz, Umut, Barış, Can …). Extend it with a custom detector rather than this list.
"""

GIVEN_NAMES = frozenset("""
Ahmet Mehmet Mustafa Ali Hüseyin Hasan İbrahim İsmail Osman Yusuf Murat Ömer Ramazan Halil Süleyman Abdullah Mahmut
Recep Salih Fatih Kemal Hakan Kadir Emre Serkan Burak Mert Onur Cem Volkan Tolga Selim Erkan Gökhan Uğur Sinan Levent
Orhan Erdem Tuncay Tarık Kerem Emir Berk Arda Efe Kaan Eren Oğuz Alper Barış Bülent Cengiz Cihan Doğan Engin Ercan
Erhan Ersin Ferhat Fikret Gökay Hamza Harun Hikmet İlker İlhan Kenan Koray Kürşat Metin Necati Nihat Okan Orçun
Özgür Rıza Sami Sedat Serdar Sertaç Tamer Taner Tayfun Turgay Ufuk Yasin Yavuz Yiğit Zafer Rüstem Ayşe Fatma Emine
Hatice Zeynep Elif Meryem Şerife Zehra Sultan Hanife Merve Esra Büşra Özlem Gamze Tuğba Derya Seda Ebru Burcu Sevgi
Aslı Ceren Dilek Duygu Ece Eda Emel Gizem Gül Gülay Gülşen Hande İpek Kübra Leyla Melek Melike Nazlı Nur Nurcan
Pınar Rabia Selin Serap Sibel Songül Şule Tülay Yasemin Yeliz Zerrin Aylin Aynur Banu Begüm Berna Betül Canan Cansu
Damla Demet Didem Dilara Esin Feride Filiz Funda Hacer Hülya Irmak Nilay Nihan Nesrin Neslihan Oya Pelin Sena Sevda
Şeyma Tuba Ümran Yağmur Zuhal
""".split())
